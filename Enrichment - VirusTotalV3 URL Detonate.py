"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_urls_as_array' block
    list_urls_as_array(container=container)

    return

@phantom.playbook_block()
def list_urls_as_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_urls_as_array() called")

    template = """%%\n{0}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="list_urls_as_array", drop_none=True)

    refang_url(container=container)

    return


@phantom.playbook_block()
def refang_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refang_url() called")

    list_urls_as_array__as_list = phantom.get_format_data(name="list_urls_as_array__as_list")

    refang_url__refanged_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    def refang(defanged_urls):
        refanged_urls = []
        
   # interate over the list of urls
        for url in defanged_urls:
            if url == None or len(url) == 0:
                # skip empty urls
                continue
                
            phantom.debug("Before refang: {}".format(url))
            
            url = url.replace("hxxp", "http")
            url = url.replace("[.]", ".")
            url = url.replace("[at]", "@")
            url = url.replace("\\", "")

            phantom.debug("After refang: {}".format(url))
            
            refanged_urls.append(url)
            
        return refanged_urls
            

    phantom.debug(list_urls_as_array__as_list)
    refang_url__refanged_url = refang(list_urls_as_array__as_list)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="refang_url:refanged_url", value=json.dumps(refang_url__refanged_url))

    fanged_urls(container=container)

    return


@phantom.playbook_block()
def fanged_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fanged_urls() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "refang_url:custom_function:refanged_urls"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="fanged_urls", drop_none=True)

    url_reputation(container=container)

    return


@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    fanged_urls__as_list = phantom.get_format_data(name="fanged_urls__as_list")

    parameters = []

    # build parameters list for 'url_reputation' call
    for fanged_urls__item in fanged_urls__as_list:
        if fanged_urls__item is not None:
            parameters.append({
                "url": fanged_urls__item,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="url_reputation", assets=["vtv3"], callback=url_result_filter)

    return


@phantom.playbook_block()
def url_result_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_result_filter() called")

    ################################################################################
    # Filters successful url reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_reputation:action_result.status", "==", "success"]
        ],
        name="url_result_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["url_reputation:action_result.status", "==", "failed"]
        ],
        name="url_result_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        update_event_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Not results found for URLs\n{0}\nConsider submitting for detonation""",
        parameters=[
            "list_urls_as_array:formatted_data"
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    list_urls_as_array = phantom.get_format_data(name="list_urls_as_array")

    parameters = []

    # build parameters list for 'update_event_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "comment": comment_formatted_string,
                "event_ids": container_artifact_item[0],
                "wait_for_confirmation": True,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["splunkes"])

    return


@phantom.playbook_block()
def normalize_score_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("normalize_score_url() called")

    ################################################################################
    # Contains custom code for normalizing score. Adjust the logic as desired in the 
    # documented sections.
    ################################################################################

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.attributes.categories","filtered-data:url_result_filter:condition_1:url_reputation:action_result.summary"])

    filtered_result_0_data___attributes_categories = [item[0] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_summary = [item[1] for item in filtered_result_0_data_url_result_filter]

    normalize_score_url__url_score_object = None
    normalize_score_url__score = None
    normalize_score_url__categories = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from math import log
    # Reference for scores: https://schema.ocsf.io/objects/reputation
    score_table = {
        "0":"Unknown",
        "1":"Very_Safe",
        "2":"Safe",
        "3":"Probably_Safe",
        "4":"Leans_Safe",
        "5":"May_not_be_Safe",
        "6":"Exercise_Caution",
        "7":"Suspicious_or_Risky",
        "8":"Possibly_Malicious",
        "9":"Probably_Malicious",
        "10":"Malicious"
    }
    
    # Assign Variables
    url_categories_list = filtered_result_0_data___attributes_categories
    url_summary_list = filtered_result_0_summary
    normalize_score_url__url_score_object = []
    normalize_score_url__score = []
    normalize_score_url__categories = []
    
    # VirusTotal v3 URL Data
    # Adjust logic as desired
    for category, summary_data in zip(url_categories_list, url_summary_list):

        # Set confidence based on percentage of vendors undetected
        # Reduce the confidence by percentage of vendors undetected.
        vendors = summary_data['harmless'] + summary_data['undetected'] + summary_data['malicious'] + summary_data['suspicious']
        confidence = 100 - int((summary_data['undetected']/vendors) * 100)
        
        # Normalize reputation on a 10 point scale based on number of malicious and suspicious divided by harmless vendors
        # This can be adjusted to include whatever logic is desired.
        suspect = summary_data['malicious'] + summary_data['suspicious']
        # If there are only harmless verdicts and no suspicious entries, set score_id to 1.
        if summary_data['harmless'] and not suspect:
            score_id = 1
        else:
            if suspect and vendors:
                # customize score calculation as desired
                log_result = log((suspect/vendors) * 100, 100) # log imported from math in global code block
                score_id = int(log_result * 10) + 3
            
                if score_id > 10:
                    score_id = 10
                    
            elif suspect == 0:
                score_id = 0
        
        categories = [cat.lower() for cat in category.values()]
        categories = list(set(categories))
        
        score = score_table[str(score_id)]
        
        # Attach final object
        normalize_score_url__url_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence, 'categories': categories})
        normalize_score_url__score.append(score)
        normalize_score_url__categories.append(categories)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="normalize_score_url:url_score_object", value=json.dumps(normalize_score_url__url_score_object))
    phantom.save_run_data(key="normalize_score_url:score", value=json.dumps(normalize_score_url__score))
    phantom.save_run_data(key="normalize_score_url:categories", value=json.dumps(normalize_score_url__categories))

    format_report_url(container=container)

    return


@phantom.playbook_block()
def format_report_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_report_url() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR analyzed URL(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` |  | {2} | https://www.virustotal.com/gui/url/{3} | VirusTotal v3 |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url",
        "normalize_score_url:custom_function:score",
        "normalize_score_url:custom_function:categories",
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_url", drop_none=True)

    build_url_output(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # Generate an observable dictionary to output into the observables data path.
    ################################################################################

    filtered_result_0_data_url_result_filter = phantom.collect2(container=container, datapath=["filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url","filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.id"])
    normalize_score_url__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_url:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_url = [item[0] for item in filtered_result_0_data_url_result_filter]
    filtered_result_0_data___id = [item[1] for item in filtered_result_0_data_url_result_filter]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from urllib.parse import urlparse
    build_url_output__observable_array = []

    # Build URL
    for url, external_id, url_object in zip(filtered_result_0_parameter_url, filtered_result_0_data___id, normalize_score_url__url_score_object):
        parsed_url = urlparse(url)
        observable_object = {
            "value": url,
            "type": "url",
            "reputation": {
                "score_id": url_object['score_id'],
                "score": url_object['score'],
                "confidence": url_object['confidence']
            },
            "attributes": {
                "hostname": parsed_url.hostname,
                "scheme": parsed_url.scheme
            },
            "categories": url_object['categories'],
            "source": "VirusTotal v3",
            "source_link": f"https://www.virustotal.com/gui/url/{external_id}"
        }
        if parsed_url.path:
            observable_object['attributes']['path'] = parsed_url.path
        if parsed_url.query:
            observable_object['attributes']['query'] = parsed_url.query
        if parsed_url.port:
            observable_object['attributes']['port'] = parsed_url.port
        
        build_url_output__observable_array.append(observable_object)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="build_url_output:observable_array", value=json.dumps(build_url_output__observable_array))

    update_event_2(container=container)

    return


@phantom.playbook_block()
def update_event_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    format_report_url = phantom.get_format_data(name="format_report_url")

    parameters = []

    # build parameters list for 'update_event_2' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "comment": format_report_url,
                "event_ids": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_event_2", assets=["splunkes"], callback=add_note_1)

    return


@phantom.playbook_block()
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_1() called")

    format_report_url = phantom.get_format_data(name="format_report_url")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_report_url, note_format="markdown", note_type="general", title="Virus Total Scan results")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return