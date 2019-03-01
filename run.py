import sys, base64, os, settings, requests, talon, re, json
from pyquery import PyQuery as pq
from apiclient import errors
from apiclient.discovery import build
from google.oauth2 import service_account
from slackclient import SlackClient


with open('category-map.json') as f:
    category_map = json.load(f)

with open('account-map.json') as f:
    account_map = json.load(f)


def find_faultfixers_building_by_account_and_name(account_id, expected_building_name_format, site_number):
    response_json = make_api_request('GET', '/buildings?accountId=' + account_id)
    expected_building_name_format_regex = re.compile(expected_building_name_format.replace('SITE_NUMBER', site_number))

    for result in response_json['results']:
        building = result['building']

        if expected_building_name_format_regex.match(building['name']):
            return building

    raise 'Could not find FaultFixers building with site number ' + site_number + ' and name format ' + expected_building_name_format_regex.pattern


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
        messages.extend(response['messages'])

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


def create_service():
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/gmail.readonly',
    ]
    SERVICE_ACCOUNT_FILE = 'service-account-key.json'

    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    delegated_credentials = credentials.with_subject(os.getenv('INBOX'))

    return build('gmail', 'v1', credentials=delegated_credentials)


def get_header(message, header_name):
    for header in message['payload']['headers']:
        if header['name'] == header_name:
            return header['value']
    raise 'Header not present: ' + header_name


def decode_base_64_data(data):
    return base64.urlsafe_b64decode(data.encode('ASCII'))


def get_part_by_mime_type(parts, mime_type):
    for part in parts:
        if part['mimeType'] == mime_type:
            return decode_base_64_data(part['body']['data'])

        if part['mimeType'] == 'multipart/alternative':
            return get_part_by_mime_type(part['parts'], mime_type)

    raise 'Part not present with mime-type: ' + mime_type


def get_body_by_mime_type(message, mime_type):
    return get_part_by_mime_type(message['payload']['parts'], mime_type)


# Example: 'ACCOUNT_NAME SITE_NUMBER SITE_NAME, Work Order WORK_ORDER_NUMBER'.
account_and_site_name = '[A-Za-z0-9!\\(\\) ]+'
subject_regex_for_work_order = re.compile('^' + account_and_site_name + ', Work Order \\d+$')
subject_regex_for_quote_required = re.compile('^' + account_and_site_name + ', Quote is required for Work Order #\\d+$')
subject_regex_for_quote_authorised = re.compile('^' + account_and_site_name + ', The quote has been authorised for the work order #\\d+$')
subject_regex_for_deescalation = re.compile('^' + account_and_site_name + ', Work Order \\d+, De-escalation: .+ Level$')
# @todo - see what the escalation email subject actually is.
subject_regex_for_escalation = re.compile('^' + account_and_site_name + ', Work Order \\d+, Escalation: .+ Level$')


def handle_work_order_email(message, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise 'No work order number'

    access_code = doc('.WOIDblockTitle:contains("Access Code")').parent().parent().find('td.WOID').text().strip()
    start_link = doc('a:contains("subcontractor link")').attr('href')
    client_contact_details = doc('td.Text2[width="325px"]').eq(0).find('p').text().strip()
    recipient_company = doc('td.Text2[width="325px"]').eq(1).find('.BlockSubtitle').text().strip()
    equipment_details = doc('td.Text2[width="325px"]').eq(2).text().strip()
    category = equipment_details.split(',')[0]
    service_request_location = doc('td.Text2[width="325px"]').eq(3)
    account_and_building_name = service_request_location.find('.BlockSubtitle').text().strip()
    account_name = account_and_building_name.split(',')[0].strip()
    site_number = account_and_building_name.split(',')[1].split('\n')[0].strip()
    description = doc('td.Text2 b:contains("Work Order Type:")').parent().text().strip()

    if not description:
        raise 'No description for work order ' + work_order_number
    if not site_number:
        raise 'No site_number for work order ' + work_order_number

    if '\nLocation:' in equipment_details:
        location_description = equipment_details.split('Location:')[1].strip().split('\n')[0]
    else:
        location_description = None

    faultfixers_category_name = category_map[category]
    faultfixers_mappings_for_client = account_map[account_name]
    faultfixers_description = 'New work order via Verisae\n\n%s\n\nEquipment details:\n%s\n\nContact details:\n%s\n\nVerisae access code: %s\n\nVerisae link: %s' % (description, equipment_details, client_contact_details, access_code, start_link)

    faultfixers_building = find_faultfixers_building_by_account_and_name(
        faultfixers_mappings_for_client['accountId'],
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


def handle_quote_required_email(message, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise 'No work order number'

    client_contact_details = doc('td.Text2[width="325"]').eq(0).find('p').text().strip()
    recipient_company = doc('td.Text2[width="325"]').eq(1).find('.BlockSubtitle').text().strip()
    equipment_details = doc('td.Text2[width="325"]').eq(2).text().strip()
    category = equipment_details.split(',')[0]
    service_request_location = doc('td.Text2[width="325"]').eq(3)
    account_and_building_name = service_request_location.find('.BlockSubtitle').text().strip()
    account_name = account_and_building_name.split(',')[0].strip()
    site_number = account_and_building_name.split(', ')[1].split(' ')[0].strip()
    description = doc('td.Text2 b:contains("Work Order Type:")').parent().text().strip()

    if not description:
        raise 'No description for work order ' + work_order_number
    if not site_number:
        raise 'No site_number for work order ' + work_order_number

    if '\nLocation:' in equipment_details:
        location_description = equipment_details.split('Location:')[1].strip().split('\n')[0]
    else:
        location_description = None

    faultfixers_category_name = category_map[category]
    faultfixers_mappings_for_client = account_map[account_name]
    faultfixers_description = 'Quote required via Verisae\n\n%s\n\nEquipment details:\n%s\n\nContact details:\n%s' % (description, equipment_details, client_contact_details)

    faultfixers_building = find_faultfixers_building_by_account_and_name(
        faultfixers_mappings_for_client['accountId'],
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


def handle_quote_authorised_email(message, doc):
    work_order_number = doc('.WOIDblockTitle:contains("Work Order")').parent().parent().find('td.WOID').text().strip()
    if not work_order_number:
        raise 'No work order number'

    access_code = doc('.WOIDblockTitle:contains("Access Code")').parent().parent().find('td.WOID').text().strip()
    if not access_code:
        raise 'No access code for work order ' + work_order_number

    start_link = doc('a:contains("subcontractor link")').attr('href')
    if not start_link:
        raise 'No start link for work order ' + work_order_number

    quote_details = doc('td.Text2:contains("Contractor Quote No.:")').text().strip().replace('\n\n', '\n')
    if not quote_details:
        raise 'No quote details for work order ' + work_order_number

    comment = 'Quote authorised via Verisae\n\nQuote details:\n%s\n\nVerisae access code: %s\n\nVerisae link: %s' % (quote_details, access_code, start_link)

    # @todo - check ticket in FF is for the same account as the email.

    payload = {
        'comment': comment,
        'commentVisibility': 'INTERNAL_TO_TEAM',
        'updaterDescription': 'Verisae integration',
    }

    response_json = make_api_request('PUT', '/tickets/' + work_order_number, payload)

    print 'Updated FaultFixers ticket %s with quote approval' % response_json['ticket']['id']


def handle_escalation_email(message, doc):
    raise '@todo - handle_escalation_email'


def handle_deescalation_email(message, doc):
    raise '@todo - handle_deescalation_email'


def handle_message(message):
    if 'parts' in message['payload']:
        full_html = get_body_by_mime_type(message, 'text/html')
    else:
        raise 'Unsupported email format'

    subject = get_header(message, 'Subject')
    email_doc = pq(full_html)

    if subject_regex_for_work_order.match(subject):
        handle_work_order_email(message, email_doc)
    elif subject_regex_for_quote_required.match(subject):
        handle_quote_required_email(message, email_doc)
    elif subject_regex_for_quote_authorised.match(subject):
        handle_quote_authorised_email(message, email_doc)
    elif subject_regex_for_deescalation.match(subject):
        handle_deescalation_email(message, email_doc)
    elif subject_regex_for_escalation.match(subject):
        handle_escalation_email(message, email_doc)
    else:
        raise 'Email\'s subject is not in supported format: %s' % subject


def make_api_request(method, endpoint, payload = None):
    headers = {
        'authorization': os.getenv('API_AUTHORIZATION_HEADER'),
        'accept': 'application/vnd.faultfixers.v11+json',
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
    service = create_service()

    list_messages = list_messages_matching_query(
        service, 'me', os.getenv('GMAIL_QUERY') + ' AND NOT label:' + os.getenv('HANDLED_LABEL_NAME'))

    print '%d messages to process' % len(list_messages)

    if len(list_messages) == 0:
        return

    for list_message in list_messages:
        print 'Getting message %s' % list_message['id']
        message = get_message(service, 'me', list_message['id'])
        handle_message(message)
        print 'Handled message %s, subject: %s' % (list_message['id'], get_header(message, 'Subject'))

        modify_message(service, 'me', list_message['id'], {
            'addLabelIds': [os.getenv('HANDLED_LABEL_ID')],
            'removeLabelIds': ['UNREAD'],
        })


def post_error_to_slack(title, error):
    if os.getenv('SLACK_ENABLED') != 'true':
        print 'Posting to Slack is not enabled'
        return

    token = os.getenv('SLACK_OAUTH_TOKEN')
    channel = os.getenv('SLACK_CHANNEL')

    sc = SlackClient(token)
    sc.api_call(
        'chat.postMessage',
        channel=channel,
        text='%s: %s' % (title, error)
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
    post_error_to_slack('Error in Verisae integration', error)
except requests.exceptions.HTTPError, error:
    print 'An error occurred: %s' % error
    print 'json: %s' % error.response.json()
    post_error_to_slack('Error in Verisae integration', error)
except:
    print 'Unexpected error:', sys.exc_info()[0]
    post_error_to_slack('Error in Verisae integration', sys.exc_info()[0])
    raise
