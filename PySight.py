def misp_check_for_previous_events(misp_instance, isight_alert):
    """
    Default: no previous event detected


    check for:
        alert_id | ['alert']['id']

    :param misp_instance:
    :type misp_instance:
    :param isight_alert:
    :type isight_alert:
    :return:
        event id if an event is there
        false if no event is present
    :rtype:
    """
    event = False

    if misp_instance is None:
        PySight_settings.logger.error("No misp instance given")
        return False

    # Based on alert id
    if isight_alert.reportId:
        result = misp_instance.search_all(isight_alert.reportId)
        PySight_settings.logger.debug("searched in MISP for %s result: %s", isight_alert.reportId, result)
        event = check_misp_all_result(result)

    # Based on Alert Url
    if isight_alert.reportLink and not event:
        from urllib import quote

        result = misp_instance.search_all(quote(isight_alert.reportLink))
        PySight_settings.logger.debug("searching in MISP for %s result: %s", isight_alert.reportLink, result)

        event = check_misp_all_result(result)

    # if one of the above returns a value:
    previous_event = event
    # this looks hacky but it to avoid exceptions if there is no ['message within the result']

    if previous_event != '' and previous_event != False and previous_event != None:
        PySight_settings.logger.debug("Will append my data to: %s", previous_event)
        event = misp_instance.get(str(previous_event))  # not get_event!
    else:
        PySight_settings.logger.debug("Will create a new event for it")

        if isight_alert.publishDate:
            new_date = time.strftime('%Y-%m-%d', time.localtime(float(isight_alert.publishDate)))
            PySight_settings.logger.debug("Date will be %s title: %s ID %s", new_date, isight_alert.title,
                                          isight_alert.reportId)
            try:
                event = misp_instance.new_event(0, 2, 0, isight_alert.title + " pySightSight " + isight_alert.reportId,
                                                new_date)
            except:
                import sys
                print("Unexpected error:", sys.exc_info()[0])
        else:
            event = misp_instance.new_event(0, 2, 0, isight_alert.title + " pySightSight " + isight_alert.reportId)

    if not event:
        PySight_settings.logger.error("Something went really wrong")
        event = misp_instance.new_event(0, 2, 0, isight_alert.title + " pySightSight " + isight_alert.reportId)
    return event


def data_text_search_title(url, public_key, private_key):
    print("text_search_title Response:")
    # title phrase search
    params = {
        'text': 'title:"Software Stack 3.1.2"'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_text_search_wildcard(url, public_key, private_key):
    print("text_search_wildcard Response:")
    # wild card text search
    params = {
        'text': 'zero-day*',
        'limit': '10',
        'offset': '0'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_search_report(url, public_key, private_key, a_reportid):
    print("text_search_wildcard Response:")
    # wild card text search
    params = {
        'reportID': a_reportid
    }
    text_search_query = '/report/' + a_reportid
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_text_search_sensitive_reports(url, public_key, private_key):
    print("text_search_sensitive_reports Response:")
    params = {
        'text': 'title:"Latin American"',
        'customerIntelOnly': True
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_search_indicators_last24_h(url, public_key, private_key):
    hours = PySight_settings.isight_last_hours
    since = int(time.time()) - hours * 60 * 60
    return data_search_indicators_since(private_key, public_key, url, since)


def data_search_indicators_since(private_key, public_key, url, since):
    print("text_search_sensitive_reports Response:")
    # since = int(time.time()) - hours * 60 * 60

    params = {
        'since': since
    }
    text_search_query = '/view/indicators?' + urllib.parse.urlencode(params)
    return isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_advanced_search_filter_indicators(url, public_key, private_key):
    print("advanced_search_filter_indicators Response:")
    # Indicator field md5
    advanced_search_query = '/search/advanced?query=md5=~8512835a95d0fabfb&fileIdentifier=[Victim;Attacker]'
    isight_prepare_data_request(url, advanced_search_query, public_key, private_key)


def data_basic_search_ip(url, public_key, private_key, ip):
    PySight_settings.logger.debug("basic_search Response")
    # Query for search
    basic_search_query = '/search/basic?ip=' + ip
    isight_prepare_data_request(url, basic_search_query, public_key, private_key)


def data_ioc(url, public_key, private_key):
    # print ("iocs Response:")
    # 30 days back start date
    startDate = int(time.time()) - 2592000
    endDate = int(time.time())
    ioc_query = '/view/iocs?' + 'startDate=' + str(startDate) + '&endDate=' + str(endDate)
    return isight_prepare_data_request(url, ioc_query, public_key, private_key)


def data_text_search_simple(url, public_key, private_key):
    print("text_search_simple Response:")
    # simple text search
    params = {
        'text': 'Stack-Based Buffer Overflow Vulnerability',
        'limit': '10',
        'offset': '0'
    }
    text_search_query = '/search/text?' + urllib.urlencode(params)
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def data_text_search_filter(url, public_key, private_key):
    try:
        print("text_search_filter Response:")
        # filter text search
        params = {
            'text': 'malware',
            'filter': 'threatScape:cyberEspionage,cyberCrime&riskRating:HIGH,LOW&language:english',
            'sortBy': 'title:asc,reportId:desc',
            'limit': '10',
            'offset': '5'
        }
        text_search_query = '/search/text?' + urllib.urlencode(params)
        print('text_search_query', text_search_query)
        isight_prepare_data_request(url, text_search_query, public_key, private_key)

        params = {
            'text': 'malware',
            'filter': 'cveId:~\'CVE\''

        }
        text_search_query = '/search/text?' + urllib.urlencode(params)
        return isight_prepare_data_request(url, text_search_query, public_key, private_key)
    except:
        return False


def data_test(url, public_key, private_key):
    PySight_settings.logger.debug("test the api:")
    # title phrase search
    text_search_query = '/test'
    isight_prepare_data_request(url, text_search_query, public_key, private_key)


def test_isight_connection():
    result = data_test(PySight_settings.isight_url, PySight_settings.isight_pub_key, PySight_settings.isight_priv_key)
    if not result:
        return False
    else:
        PySight_settings.logger.debug("else %s", result)
        return True

        # Returns an intelligence report in a specific format and at a specific level of detail.


def misp_process_isight_alert(a_result):
    """

    :param a_result:
    :type a_result:
    """

    global end
    for i in a_result['message']:
        PySight_settings.logger.debug("  %s current element %s", len(a_result['message']), i)

        # USING THREADS to proceed with the resulting JSON
        if PySight_settings.use_threading:
            t = threading.Thread(target=isight_process_alert_content_element, args=(i,))
            t.start()
        else:
            # NO THREADING

            isight_process_alert_content_element(i)
            PySight_settings.logger.debug("Sleeping for %s seconds", PySight_settings.time_sleep)
            time.sleep(PySight_settings.time_sleep)
    end = timer()


if __name__ == '__main__':
    misp_instance = get_misp_instance()

    # TODO: not yet finished to parse the report!
    # data_search_report(isight_url, public_key, private_key, "16-00014614")

    # this is to log the time used to run the script
    from timeit import default_timer as timer

    start = timer()
    result = data_search_indicators_last24_h(PySight_settings.isight_url, PySight_settings.isight_pub_key,
                                             PySight_settings.isight_priv_key)

    misp_process_isight_alert(result)

    print("Time taken %s", end - start)

    # data_test(isight_url,public_key,private_key)
    #
    # data_ioc(url, public_key, private_key)
    # data_text_search_simple(isight_url, public_key, private_key)
    # data_text_search_filter(isight_url, public_key, private_key)
    # data_text_search_title(url, public_key, private_key)
    # data_text_search_wildcard(url, public_key, private_key)
    # data_text_search_sensitive_reports(isight_url, public_key, private_key)
    # data_advanced_search_filter_indicators(url, public_key, private_key)
