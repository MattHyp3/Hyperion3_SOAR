"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_url' block
    get_url(container=container)
    # call 'get_domain' block
    get_domain(container=container)

    return

@phantom.playbook_block()
def threatsteam_url_rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threatsteam_url_rep() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_refang_url_as_list__as_list = phantom.get_format_data(name="get_refang_url_as_list__as_list")

    parameters = []

    # build parameters list for 'threatsteam_url_rep' call
    for get_refang_url_as_list__item in get_refang_url_as_list__as_list:
        if get_refang_url_as_list__item is not None:
            parameters.append({
                "url": get_refang_url_as_list__item,
                "limit": 10,
                "extend_source": False,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="threatsteam_url_rep", assets=["threatstream"], callback=threatstream_rep)

    return


@phantom.playbook_block()
def threatstream_rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threatstream_rep() called")

    id_value = container.get("id", None)
    threatsteam_url_rep_result_data = phantom.collect2(container=container, datapath=["threatsteam_url_rep:action_result.data","threatsteam_url_rep:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'threatstream_rep' call
    for threatsteam_url_rep_result_item in threatsteam_url_rep_result_data:
        parameters.append({
            "name": "ThreatStream Results",
            "tags": None,
            "label": "reputation",
            "severity": None,
            "cef_field": "threatstream_result",
            "cef_value": threatsteam_url_rep_result_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="threatstream_rep", callback=decision_2)

    return


@phantom.playbook_block()
def threatstream_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threatstream_results() called")

    template = """*Threat Stream Results*\n\n{1}\n\nConfidence: {0}\nThreat Score: {2}\nIndicator: {3}\nSource: {4}\n"""

    # parameter list for template variable replacement
    parameters = [
        "threatsteam_url_rep:action_result.data.*.confidence",
        "threatsteam_url_rep:action_result.message",
        "threatsteam_url_rep:action_result.data.*.threatscore",
        "threatsteam_url_rep:action_result.data.*.itype",
        "threatsteam_url_rep:action_result.data.*.source"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="threatstream_results")

    add_note_10(container=container)

    return


@phantom.playbook_block()
def refang_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refang_url() called")

    ################################################################################
    # Grabs the url field from the event which is defanged and modifies to for better 
    # searching against threat sources.
    ################################################################################

    get_url__as_list = phantom.get_format_data(name="get_url__as_list")

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
            

    phantom.debug(get_url__as_list)
    refang_url__refanged_url = refang(get_url__as_list)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="refang_url:refanged_url", value=json.dumps(refang_url__refanged_url))

    get_refang_url_as_list(container=container)

    return


@phantom.playbook_block()
def get_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_url() called")

    ################################################################################
    # gets the URL from the event artifact
    # 
    # Specifically pulls the 'urls' field which is passed through from Splunk ES.
    ################################################################################

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.artifact_url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_url", drop_none=True)

    refang_url(container=container)

    return


@phantom.playbook_block()
def add_note_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_10() called")

    threatstream_results = phantom.get_format_data(name="threatstream_results")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=threatstream_results, note_format="markdown", note_type="general", title="threatstream results")

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["threatsteam_url_rep:action_result.data.*.confidence", "==", None]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        no_results_seen(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    threatstream_results(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def no_results_seen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_results_seen() called")

    template = """*Threat Stream Results*\n\nNo results seen in Threat Stream\n"""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="no_results_seen")

    add_note_5(container=container)

    return


@phantom.playbook_block()
def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_5() called")

    no_results_seen = phantom.get_format_data(name="no_results_seen")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=no_results_seen, note_format="markdown", note_type="general", title="Threat Stream Results")

    return


@phantom.playbook_block()
def get_refang_url_as_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_refang_url_as_list() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "refang_url:custom_function:refanged_url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_refang_url_as_list")

    threatsteam_url_rep(container=container)

    return


@phantom.playbook_block()
def get_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_domain() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.artifact_domain"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_domain", drop_none=True)

    threatstream_domain_rep(container=container)

    return


@phantom.playbook_block()
def threatstream_domain_rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threatstream_domain_rep() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_domain = phantom.get_format_data(name="get_domain")

    parameters = []

    if get_domain is not None:
        parameters.append({
            "limit": 10,
            "domain": get_domain,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="threatstream_domain_rep", assets=["threatstream"], callback=domain_rep_result)

    return


@phantom.playbook_block()
def domain_rep_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_rep_result() called")

    id_value = container.get("id", None)
    threatstream_domain_rep_result_data = phantom.collect2(container=container, datapath=["threatstream_domain_rep:action_result.summary","threatstream_domain_rep:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'domain_rep_result' call
    for threatstream_domain_rep_result_item in threatstream_domain_rep_result_data:
        parameters.append({
            "name": "ThreatStream Domain Result",
            "tags": None,
            "label": "reputation",
            "severity": None,
            "cef_field": "threatsteam_domain_rep",
            "cef_value": threatstream_domain_rep_result_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="domain_rep_result")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return