# coding: utf-8

import sys, base64, os, settings, requests, talon, re, json
from pyquery import PyQuery as pq
from apiclient import errors
from apiclient.discovery import build
from google.oauth2 import service_account
from slackclient import SlackClient


def create_gmail_service():
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/gmail.readonly',
    ]
    SERVICE_ACCOUNT_FILE = 'service-account-key.json'

    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    delegated_credentials = credentials.with_subject(os.getenv('INBOX'))

    return build('gmail', 'v1', credentials=delegated_credentials)


service = create_gmail_service()

with open('category-map.json') as f:
    category_map = json.load(f)

with open('account-map.json') as f:
    account_map = json.load(f)

# Example: 'ACCOUNT_NAME SITE_NUMBER SITE_NAME, Work Order WORK_ORDER_NUMBER'.
account_and_site_name = '[A-Za-z0-9!\\(\\)\\.:\\- ]+'
subject_regex_for_work_order = re.compile('^' + account_and_site_name + ', Work Order \\d+$')
subject_regex_for_quote_required = re.compile('^' + account_and_site_name + ', Quote is required for Work Order #\\d+$')
subject_regex_for_quote_authorised = re.compile('^' + account_and_site_name + ', The quote has been authorised for the work order #\\d+$')
subject_regex_for_quote_rejected = re.compile('^' + account_and_site_name + ', Quote has been rejected for work order #\\d+$')
subject_regex_for_deescalation = re.compile('^' + account_and_site_name + ', Work Order \\d+, De-escalation: .+ Level$')
subject_regex_for_escalation = re.compile('^' + account_and_site_name + ', Work Order \\d+, Escalation: .+ Level$')
subject_regex_for_work_order_has_a_new_note = re.compile('^' + account_and_site_name + ', Work Order \\d+ has a new note$')
subject_regex_for_cppm_attachment_sla_approaching = re.compile('^' + account_and_site_name + ' Alert: CPPM Attachment SLA Approaching$')
subject_regex_for_cancellation = re.compile('^Cancel Work Order \\d+, ' + account_and_site_name + '$')
subject_regex_for_recall = re.compile('^' + account_and_site_name + ', Recalled Work Order \\d+ \\(Instance \\d+\\)$')

subject_regexes_that_will_create_ticket = [
    subject_regex_for_work_order,
    subject_regex_for_quote_required,
]


def find_faultfixers_buildings_by_account_ids(account_ids):
    response_json = make_api_request('GET', '/buildings?account=' + ','.join(account_ids))
    return map(lambda result: result['building'], response_json['results'])


def find_faultfixers_building_by_account_and_name(account_ids, expected_building_name_format, site_number):
    buildings = find_faultfixers_buildings_by_account_ids(account_ids)
    expected_name_regex = re.compile(expected_building_name_format.replace('SITE_NUMBER', site_number))

    for building in buildings:
        if expected_name_regex.match(building['name']):
            return building

    raise Exception(
        'Could not find FaultFixers building with name format %s in accounts %s' %
        (expected_name_regex.pattern, ','.join(account_ids))
    )


def find_faultfixers_ticket_by_id(id):
    if not id:
        raise Exception('No ticket ID given')

    response_json = make_api_request('GET', '/tickets/' + id)
    ticket = response_json['ticket']
    ticket['building'] = response_json['building']
    return ticket


def get_faultfixers_category_name_by_verisae_name(verisae_name):
    if verisae_name not in category_map:
        raise Exception('Category name is not in the map: ' + verisae_name)

    return category_map[verisae_name]


def get_account_mappings_by_name(account_name):
    if account_name not in account_map:
        raise Exception('Account name is not in mapping: ' + account_name)

    return account_map[account_name]


def ensure_building_is_owned_by_account_name(building_id, account_name):
    if not building_id:
        raise Exception('No building ID given')
    if not account_name:
        raise Exception('No account name given')

    account_mappings = get_account_mappings_by_name(account_name)
    buildings = find_faultfixers_buildings_by_account_ids(account_mappings['accountIds'])

    for building in buildings:
        if building['id'] == building_id:
            return

    raise Exception('Building %s is not owned by %s' % (building_id, account_name))


def apply_description_redactions(description):
    description = description.strip()
    # Remove costs from descriptions to avoid wage politics.
    description = re.sub(u'Not To Exceed \\(NTE\\): \u00a3[\\d+\\.]+\n?', '', description)
    description = description.strip()
    return description


def list_messages_matching_query(service, user_id, query=''):
    """List all Messages of the user's mailbox matching the query.

    Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    query: String used to filter messages returned.
    Eg.- 'from:user@some_domain.com' for Messages from a particular sender.

    Returns:
    List of Messages that match the criteria of the query. Note that the
    returned list contains Message IDs, you must use get with the
    appropriate ID to get the details of a Message.
    """
    response = service.users().messages().list(userId=user_id,
                                               q=query).execute()

    messages = []
    if 'messages' in response:
        messages.extend(response['messages'])

    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        response = service.users().messages().list(
            userId=user_id, q=query, pageToken=page_token).execute()

        # 'messages' will not be present in the next page if the total available messages is the same size as the first
        # page. In other words, if the Gmail page size is 100 and there are exactly 100 available messages, the first
        # response will return 100 and a 'nextPageToken', and the second page will return nothing.
        if 'messages' in response:
            messages.extend(response['messages'])

    # Sort by oldest first. Gmail always returns with the newest first -- this is not configurable.
    messages.reverse()

    return messages


def get_message(service, user_id, message_id):
    """Get a message from the user's mailbox.

    Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message_id: The message ID.
    """
    return service.users().messages().get(userId=user_id, id=message_id).execute()


def modify_message(service, user_id, message_id, modifications):
    """Add a label to a message.

    Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message_id: The message ID.
    modifications: The modifications.
    """
    return service.users().messages().modify(userId=user_id, id=message_id, body=modifications).execute()


def get_header(message, header_name):
    for header in message['payload']['headers']:
        if header['name'] == header_name:
            return header['value']
    raise Exception('Header not present: ' + header_name)


def decode_base_64_data(data):
    return base64.urlsafe_b64decode(data.encode('ASCII'))


def get_part_by_mime_type(parts, mime_type):
    for part in parts:
        if part['mimeType'] == mime_type:
            return decode_base_64_data(part['body']['data'])

        if part['mimeType'] == 'multipart/alternative':
            return get_part_by_mime_type(part['parts'], mime_type)

    raise Exception('Part not present with mime-type: ' + mime_type)


def get_body_by_mime_type(message, mime_type):
    return get_part_by_mime_type(message['payload']['parts'], mime_type)


def get_notices(doc):
    notices_cell = doc('td.MsgBlockTitle3:contains("Notices")')
    if notices_cell:
        return notices_cell.parent().next('tr').find('td').text().strip()
    else:
        return None


def handle_work_order_email(message, subject, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    access_code = doc('.WOIDblockTitle:contains("Access Code")').parent().parent().find('td.WOID').text().strip()
    start_link = doc('a:contains("subcontractor link")').attr('href')
    client_contact_details = doc('td.Text2[width="325px"]').eq(0).find('p').text().strip()
    contractor_company = doc('td.Text2[width="325px"]').eq(1).find('.BlockSubtitle').text().strip()
    equipment_details = doc('td.Text2[width="325px"]').eq(2).text().strip()
    category = equipment_details.split(',')[0]
    service_request_location = doc('td.Text2[width="325px"]').eq(3)
    account_and_building_name = service_request_location.find('.BlockSubtitle').text().strip()
    account_name = account_and_building_name.split(',')[0].strip()

    site_number = account_and_building_name.split(',')[1].split('\n')[0].strip()
    if not site_number:
        raise Exception('No site_number for work order ' + work_order_number)

    description = doc('td.Text2 b:contains("Work Order Type:")').parent().text().strip()
    if not description:
        raise Exception('No description for work order ' + work_order_number)
    description = apply_description_redactions(description)

    if '\nLocation:' in equipment_details:
        location_description = equipment_details.split('Location:')[1].strip().split('\n')[0]
    else:
        location_description = None

    faultfixers_category_name = get_faultfixers_category_name_by_verisae_name(category)
    faultfixers_mappings_for_client = get_account_mappings_by_name(account_name)
    faultfixers_description = 'New work order via Verisae\n\n%s\n\nEquipment details:\n%s\n\nContact details:\n%s\n\nVerisae access code: %s\n\nVerisae link: %s' % (description, equipment_details, client_contact_details, access_code, start_link)

    notices = get_notices(doc)
    if notices:
        faultfixers_description += '\n\nNotices:\n%s' % notices

    faultfixers_building = find_faultfixers_building_by_account_and_name(
        faultfixers_mappings_for_client['accountIds'],
        faultfixers_mappings_for_client['buildingNameFormat'],
        site_number
    )

    payload = {
        'category': faultfixers_category_name,
        'description': faultfixers_description,
        'locationDescription': location_description,
        'building': faultfixers_building['id'],
        'customFriendlyId': work_order_number,
        'reporterDescription': 'Verisae integration',
        'type': 'REACTIVE',
        'privacy': 'PRIVATE',
    }

    response_json = make_api_request('POST', '/tickets', payload)

    print 'Created FaultFixers ticket %s' % response_json['ticket']['id']


def handle_quote_required_email(message, subject, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    client_contact_details = doc('td.Text2[width="325"]').eq(0).find('p').text().strip()
    contractor_company = doc('td.Text2[width="325"]').eq(1).find('.BlockSubtitle').text().strip()
    equipment_details = doc('td.Text2[width="325"]').eq(2).text().strip()
    category = equipment_details.split(',')[0]
    service_request_location = doc('td.Text2[width="325"]').eq(3)
    account_and_building_name = service_request_location.find('.BlockSubtitle').text().strip()
    account_name = account_and_building_name.split(',')[0].strip()

    site_number = account_and_building_name.split(', ')[1].split(' ')[0].strip()
    if not site_number:
        raise Exception('No site_number for work order ' + work_order_number)

    description = doc('td.Text2 b:contains("Work Order Type:")').parent().text().strip()
    if not description:
        raise Exception('No description for work order ' + work_order_number)
    description = apply_description_redactions(description)

    if '\nLocation:' in equipment_details:
        location_description = equipment_details.split('Location:')[1].strip().split('\n')[0]
    else:
        location_description = None

    faultfixers_category_name = get_faultfixers_category_name_by_verisae_name(category)
    faultfixers_mappings_for_client = get_account_mappings_by_name(account_name)
    faultfixers_description = 'Quote required via Verisae\n\n%s\n\nEquipment details:\n%s\n\nContact details:\n%s' % (description, equipment_details, client_contact_details)

    faultfixers_building = find_faultfixers_building_by_account_and_name(
        faultfixers_mappings_for_client['accountIds'],
        faultfixers_mappings_for_client['buildingNameFormat'],
        site_number
    )

    payload = {
        'building': faultfixers_building['id'],
        'category': faultfixers_category_name,
        'description': faultfixers_description,
        'locationDescription': location_description,
        'customFriendlyId': work_order_number,
        'reporterDescription': 'Verisae integration',
        'type': 'REACTIVE',
        'privacy': 'PRIVATE',
    }

    response_json = make_api_request('POST', '/tickets', payload)

    print 'Created FaultFixers ticket %s' % response_json['ticket']['id']


def handle_quote_authorised_email(message, subject, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    access_code = doc('.WOIDblockTitle:contains("Access Code")').parent().parent().find('td.WOID').text().strip()
    if not access_code:
        raise Exception('No access code for work order ' + work_order_number)

    start_link = doc('a:contains("subcontractor link")').attr('href')
    if not start_link:
        raise Exception('No start link for work order ' + work_order_number)

    quote_details = doc('td.Text2:contains("Contractor Quote No.:")').text().strip().replace('\n\n', '\n')
    if not quote_details:
        raise Exception('No quote details for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2[width="325"]').eq(1).find('.BlockSubtitle').text().strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    # `quote_details` is deliberately not included in the ticket comment to avoid wage politics.

    comment = 'Quote authorised via Verisae\n\nVerisae access code: %s\n\nVerisae link: %s' % (access_code, start_link)

    payload = {
        'comment': comment,
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with quote approval' % response_json['ticket']['id']


def handle_quote_rejected_email(message, subject, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2[width="325"]').eq(1).find('.BlockSubtitle').text().strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    payload = {
        'comment': 'Quote rejected via Verisae',
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with quote approval' % response_json['ticket']['id']


def handle_escalation_email(message, subject, doc):
    level = subject.split('Escalation: ')[1].strip()

    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    details = doc('td.Text2:contains("Escalation User:")').text().strip()
    if not details:
        raise Exception('No escalation details for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2[colspan="3"]').eq(2).text().strip().split('\n')[0].strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    comment = 'Escalation via Verisae\n\n%s\n\n%s' % (level, details)

    payload = {
        'comment': comment,
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with de-escalation' % response_json['ticket']['id']


def handle_deescalation_email(message, subject, doc):
    level = subject.split('De-escalation: ')[1].strip()

    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    details = doc('td.Text2:contains("De-escalation User:")').text().strip()
    if not details:
        raise Exception('No de-escalation details for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2[colspan="3"]').eq(2).text().strip().split('\n')[0].strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    comment = 'De-escalation via Verisae\n\n%s\n\n%s' % (level, details)

    payload = {
        'comment': comment,
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with de-escalation' % response_json['ticket']['id']


def handle_work_order_has_new_note_email(message, subject, doc):
    work_order_number = subject.split('Work Order ')[1].split(' has a new note')[0].strip()
    if not work_order_number:
        raise Exception('No work order number')

    note_type = doc('td.Text2:contains("Note Type:")').text().strip()
    if not note_type:
        raise Exception('No note type for work order ' + work_order_number)

    note = doc('td.SmallBold:contains("Note:")').text().strip()
    if not note:
        raise Exception('No note for work order ' + work_order_number)

    by = doc('td.Text2:contains("This work order has been updated by ")').text().strip()
    by = by.replace('This work order has been updated by ', '')
    by = by.replace(' with the following information:', '')
    if not by:
        raise Exception('No user for note for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2').eq(1).text().strip().split('\n')[0].strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    payload = {
        'comment': '%s\n\n%s' % (note_type, note),
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration on behalf of "%s"' % by,
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with note' % response_json['ticket']['id']


def handle_cppm_attachment_sla_approaching(message, subject, doc):
    work_order_number = doc('td:contains("Work Order: ")').text().replace('Work Order: ', '').strip()
    if not work_order_number:
        raise Exception('No work order number')

    comment = doc('td:contains(" requires compliancy documentation ")').text().strip()
    if not comment:
        raise Exception('No comment for work order ' + work_order_number)

    sla = doc('td:contains("Attachment SLA: ")').text().strip()
    if not sla:
        raise Exception('No attachment SLA for work order ' + work_order_number)

    contractor_company = doc('td:contains("Contractor: ")').text().replace('Contractor: ', '').strip()
    if not contractor_company:
        raise Exception('No contractor for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    payload = {
        'comment': '%s\n\n%s' % (comment, sla),
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with CPPM attachment SLA approaching' % response_json['ticket']['id']


def handle_cancellation_email(message, subject, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    details = doc('td.Text2:contains("Cancel Reason:")').text().strip()
    if not details:
        raise Exception('No cancellation details for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2[width="325px"]').eq(1).text().strip().split('\n')[0].strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    comment = 'Cancelled via Verisae\n\n%s' % details

    payload = {
        'comment': comment,
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with cancellation' % response_json['ticket']['id']


def handle_recall_email(message, subject, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise Exception('No work order number')

    details = doc('td.Text2:contains("Recall Reason:")').text().strip()
    if not details:
        raise Exception('No recall details for work order ' + work_order_number)

    ticket = find_faultfixers_ticket_by_id(work_order_number)
    contractor_company = doc('td.Text2[width="325px"]').eq(1).text().strip().split('\n')[0].strip()
    ensure_building_is_owned_by_account_name(ticket['building']['id'], contractor_company)

    details = details.split('\n')
    details = filter(lambda line: line.startswith('Recall'), details)
    details = '\n\n'.join(details)

    comment = 'Recalled via Verisae\n\n%s' % details

    payload = {
        'comment': comment,
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with recall' % response_json['ticket']['id']


def handle_message(message, subject):
    if 'parts' in message['payload']:
        full_html = get_body_by_mime_type(message, 'text/html')
    else:
        raise Exception('Unsupported email format')

    email_doc = pq(full_html)

    if subject_regex_for_work_order.match(subject):
        handle_work_order_email(message, subject, email_doc)
    elif subject_regex_for_quote_required.match(subject):
        handle_quote_required_email(message, subject, email_doc)
    elif subject_regex_for_quote_authorised.match(subject):
        handle_quote_authorised_email(message, subject, email_doc)
    elif subject_regex_for_quote_rejected.match(subject):
        handle_quote_rejected_email(message, subject, email_doc)
    elif subject_regex_for_deescalation.match(subject):
        handle_deescalation_email(message, subject, email_doc)
    elif subject_regex_for_escalation.match(subject):
        handle_escalation_email(message, subject, email_doc)
    elif subject_regex_for_work_order_has_a_new_note.match(subject):
        handle_work_order_has_new_note_email(message, subject, email_doc)
    elif subject_regex_for_cppm_attachment_sla_approaching.match(subject):
        handle_cppm_attachment_sla_approaching(message, subject, email_doc)
    elif subject_regex_for_cancellation.match(subject):
        handle_cancellation_email(message, subject, email_doc)
    elif subject_regex_for_recall.match(subject):
        handle_recall_email(message, subject, email_doc)
    else:
        raise Exception('Email\'s subject is not in supported format: %s' % subject)

    print 'Handled message %s, subject: %s' % (message['id'], subject)
    print

    modify_message(service, 'me', message['id'], {
        'addLabelIds': [os.getenv('HANDLED_LABEL_ID')],
        'removeLabelIds': ['UNREAD'],
    })

def make_api_request(method, endpoint, payload = None):
    print 'Making API request: %s %s' % (method, endpoint)

    headers = {
        'authorization': os.getenv('API_AUTHORIZATION_HEADER'),
        'accept': 'application/vnd.faultfixers.v13+json',
        'content-type': 'application/json',
    }
    response = getattr(requests, method.lower())(
        os.getenv('API_BASE') + endpoint,
        headers=headers,
        json=payload
    )
    response.raise_for_status()

    return response.json()


def run():
    list_messages = list_messages_matching_query(
        service, 'me', os.getenv('GMAIL_QUERY') + ' AND NOT label:' + os.getenv('HANDLED_LABEL_NAME'))

    print '%d messages to process' % len(list_messages)

    if len(list_messages) == 0:
        return

    print

    delayed = []

    for list_message in list_messages:
        message = get_message(service, 'me', list_message['id'])
        subject = get_header(message, 'Subject')
        print 'Got message %s, subject: %s' % (message['id'], subject)

        is_ticket_creating = False
        for subject_regex_that_will_create_ticket in subject_regexes_that_will_create_ticket:
            if subject_regex_that_will_create_ticket.match(subject):
                is_ticket_creating = True

        if is_ticket_creating:
            handle_message(message, subject)
        else:
            delayed.append((message, subject))
            print 'Delayed handling of message because it is not ticket-creating'
            print

    for d in delayed:
        message = d[0]
        subject = d[1]
        handle_message(message, subject)


def post_error_to_slack(error):
    if os.getenv('SLACK_ENABLED') != 'true':
        print 'Posting to Slack is not enabled'
        return

    token = os.getenv('SLACK_OAUTH_TOKEN')
    channel = os.getenv('SLACK_CHANNEL')

    sc = SlackClient(token)
    sc.api_call(
        'chat.postMessage',
        channel=channel,
        text='Error in Verisae integration: %s' % error
    )

try:
    run()
except errors.HttpError, error:
    print 'An error occurred: %s' % error
    print 'content: %s' % error.content
    print 'error_details: %s' % error.error_details
    print 'message: %s' % error.message
    print 'resp: %s' % error.resp
    print 'uri: %s' % error.uri
    post_error_to_slack(error)
except requests.exceptions.HTTPError, error:
    print 'An error occurred: %s' % error
    print 'response: %s' % error.response
    try:
        print 'json: %s' % error.response.json()
    except:
        print 'no json in response'
    post_error_to_slack(error)
except:
    print 'Unexpected error:', sys.exc_info()[1]
    post_error_to_slack(sys.exc_info()[1])
    raise
