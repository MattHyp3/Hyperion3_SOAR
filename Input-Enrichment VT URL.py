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

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="list_urls_as_array", drop_none=True)

    refang_urls(container=container)

    return


@phantom.playbook_block()
def refang_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refang_urls() called")

    ################################################################################
    # replaced hxxp etc for http making the urls live again for submission 
    ################################################################################

    list_urls_as_array__as_list = phantom.get_format_data(name="list_urls_as_array__as_list")

    refang_urls__refanged_url = None

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

    phantom.save_run_data(key="refang_urls:refanged_url", value=json.dumps(refang_urls__refanged_url))

    gather_url_list(container=container)

    return


@phantom.playbook_block()
def gather_url_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("gather_url_list() called")

    ################################################################################
    # Gathers the refanged URLs as an array to run 1 or more URLs against Virus Total 
    # 
    ################################################################################

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "refang_urls:custom_function:refanged_url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="gather_url_list", drop_none=True)

    get_url_reputation(container=container)

    return


@phantom.playbook_block()
def get_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    gather_url_list__as_list = phantom.get_format_data(name="gather_url_list__as_list")

    parameters = []

    # build parameters list for 'get_url_reputation' call
    for gather_url_list__item in gather_url_list__as_list:
        if gather_url_list__item is not None:
            parameters.append({
                "url": gather_url_list__item,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="get_url_reputation", assets=["vtv3"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_url_reputation:action_result.status", "==", "failed"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_results_found_comment_to_splunk_es(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="No Results Found")

    add_no_results_comment_to_splunk_es(container=container)

    return


@phantom.playbook_block()
def add_no_results_comment_to_splunk_es(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_no_results_comment_to_splunk_es() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""No VirusTotal Result found.\n\nConsider sending URL/s for manual detonation if URL is not sensitive.\n""",
        parameters=[
            ""
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'add_no_results_comment_to_splunk_es' call
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

    phantom.act("update event", parameters=parameters, name="add_no_results_comment_to_splunk_es", assets=["splunkes"])

    return


@phantom.playbook_block()
def add_results_found_comment_to_splunk_es(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_results_found_comment_to_splunk_es() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Result Summary\n{0}\n\nLink to results\n{1}\n""",
        parameters=[
            "get_url_reputation:action_result.message",
            "get_url_reputation:action_result.data.*.links.self"
        ])

    get_url_reputation_result_data = phantom.collect2(container=container, datapath=["get_url_reputation:action_result.message","get_url_reputation:action_result.data.*.links.self","get_url_reputation:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'add_results_found_comment_to_splunk_es' call
    for get_url_reputation_result_item in get_url_reputation_result_data:
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

    phantom.act("update event", parameters=parameters, name="add_results_found_comment_to_splunk_es", assets=["splunkes"], callback=filter_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")



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