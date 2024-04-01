"""
Accepts a URL or vault_id and detonates the object in VirusTotal&#39;s sandbox. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.\n\nRef: https://d3fend.mitre.org/technique/d3f:DynamicAnalysis
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



from math import log
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'url_detonation_1' block
    url_detonation_1(container=container)

    return

@phantom.playbook_block()
def url_detonation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_detonation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries VirusTotal for information about the provided URL(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'url_detonation_1' call
    for playbook_input_url_item in playbook_input_url:
        if playbook_input_url_item[0] is not None:
            parameters.append({
                "url": playbook_input_url_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="url_detonation_1", assets=["vtv3"], callback=url_detonate_filter)

    return


@phantom.playbook_block()
def normalize_score_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("normalize_score_url() called")

    ################################################################################
    # This block uses custom code for normalizing score. Adjust the logic as desired 
    # in the documented sections.
    ################################################################################

    filtered_result_0_data_url_detonate_filter = phantom.collect2(container=container, datapath=["filtered-data:url_detonate_filter:condition_1:url_detonation_1:action_result.data.*.attributes.categories","filtered-data:url_detonate_filter:condition_1:url_detonation_1:action_result.summary"])

    filtered_result_0_data___attributes_categories = [item[0] for item in filtered_result_0_data_url_detonate_filter]
    filtered_result_0_summary = [item[1] for item in filtered_result_0_data_url_detonate_filter]

    normalize_score_url__url_score_object = None
    normalize_score_url__score = None
    normalize_score_url__categories = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug("filtered_result_0_data___attributes_categories: {}".format(filtered_result_0_data___data_attributes_results___category))
    #phantom.debug("filtered_result_0_summary: {}".format(filtered_result_0_summary))
    #phantom.debug("filtered_result_1_data___scans: {}".format(filtered_result_1_data___scans))
    #phantom.debug("url_detonation_result_item_0: {}".format(url_detonation_result_item_0))
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
    
    url_categories_list = filtered_result_0_data___attributes_categories
    url_summary_list = filtered_result_0_summary
    normalize_score_url__url_score_object = []
    normalize_score_url__score = []
    normalize_score_url__categories = []

    #for category, summary_data in zip(url_categories_list, url_summary_list):
    for category, summary_data in zip(url_categories_list, url_summary_list):
        
        # Set confidence based on percentage of vendors undetected
        # Reduce the confidence by percentage of vendors undetected.
        vendors = summary_data['harmless'] + summary_data['undetected'] + summary_data['malicious'] + summary_data['suspicious']
        confidence = 100 - int((summary_data['undetected']/vendors) * 100)
        
        #phantom.debug("vendors: {}".format(vendors))
        #phantom.debug("confidence: {}".format(confidence))

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
        
        if category != None:
            categories = [cat.lower() for cat in category.values()]
            categories = list(set(categories))
        else:
            categories = []
        
        score = score_table[str(score_id)]

        # Attach final object
        normalize_score_url__url_score_object.append({'score': score, 'score_id': score_id, 'confidence': confidence, 'categories': categories})
        normalize_score_url__score.append(score)
        normalize_score_url__categories.append(categories)
        #phantom.debug("normalize_score_url__url_score_object: {}".format(normalize_score_url__url_score_object))
        #phantom.debug("normalize_score_url__score: {}".format(normalize_score_url__score))
        #phantom.debug("normalize_score_url__categories: {}".format(normalize_score_url__categories))


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

    template = """SOAR analyzed URL(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` | {1} | {2} | https://www.virustotal.com/gui/url/{3} | VirusTotal v3 |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:input_filter:condition_1:playbook_input:url",
        "normalize_score_url:custom_function:score",
        "normalize_score_url:custom_function:categories",
        "filtered-data:url_detonate_filter:condition_1:url_detonation_1:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_url")

    build_url_output(container=container)

    return


@phantom.playbook_block()
def build_url_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_url_output() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    filtered_result_0_data_url_detonate_filter = phantom.collect2(container=container, datapath=["filtered-data:url_detonate_filter:condition_1:url_detonation_1:action_result.parameter.url","filtered-data:url_detonate_filter:condition_1:url_detonation_1:action_result.data.*.id"])
    normalize_score_url__url_score_object = json.loads(_ if (_ := phantom.get_run_data(key="normalize_score_url:url_score_object")) != "" else "null")  # pylint: disable=used-before-assignment

    filtered_result_0_parameter_url = [item[0] for item in filtered_result_0_data_url_detonate_filter]
    filtered_result_0_data___id = [item[1] for item in filtered_result_0_data_url_detonate_filter]

    build_url_output__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from urllib.parse import urlparse
    build_url_output__observable_array = []
    
    # Build URL
    for url, external_id, url_object in zip(filtered_result_0_parameter_url, filtered_result_0_data___id, normalize_score_url__url_score_object):
        parsed_url = urlparse(url)
        phantom.debug("parsed_url: {}, url_object: {}".format(parsed_url, url_object))
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

    return


@phantom.playbook_block()
def url_detonate_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_detonate_filter() called")

    ################################################################################
    # Filters successful url reputation results.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["url_detonation_1:action_result.status", "==", "success"]
        ],
        name="url_detonate_filter:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        normalize_score_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report_file = phantom.get_format_data(name="format_report_file")
    format_report_url = phantom.get_format_data(name="format_report_url")
    build_url_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_url_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment
    build_file_output__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="build_file_output:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    observable_combined_value = phantom.concatenate(build_url_output__observable_array, build_file_output__observable_array)
    markdown_report_combined_value = phantom.concatenate(format_report_file, format_report_url)

    output = {
        "observable": observable_combined_value,
        "markdown_report": markdown_report_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return