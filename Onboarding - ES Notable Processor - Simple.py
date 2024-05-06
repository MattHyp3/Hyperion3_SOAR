"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'mark_evidence_artifact' block
    mark_evidence_artifact(container=container)

    return

@phantom.playbook_block()
def mark_evidence_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("mark_evidence_artifact() called")

    id_value = container.get("id", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'mark_evidence_artifact' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "container": id_value,
            "content_type": "event_id",
            "input_object": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_artifact", callback=asset_get_splunk)

    return


@phantom.playbook_block()
def asset_get_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_get_splunk() called")

    parameters = []

    parameters.append({
        "asset": "splunk",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="asset_get_splunk", callback=asset_get_splunk_callback)

    return


@phantom.playbook_block()
def asset_get_splunk_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_get_splunk_callback() called")

    
    format_es_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_es_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_event_name(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_multi_urls(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_single_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def format_es_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_es_url() called")

    ################################################################################
    # Format a URL for the link back to the Notable ID. Change the port number as 
    # needed.
    ################################################################################

    template = """https://splunkes.com/:8000/en-US/app/SplunkEnterpriseSecuritySuite/incident_review?earliest={1}&latest=now&search=event_id%3D{2}"""

    # parameter list for template variable replacement
    parameters = [
        "asset_get_splunk:custom_function_result.data.configuration.device",
        "artifact:*.cef.info_min_time",
        "artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_url", scope="all")

    pin_es_url(container=container)

    return


@phantom.playbook_block()
def pin_es_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_es_url() called")

    ################################################################################
    # Pin the Enterprise Security URL
    ################################################################################

    format_es_url = phantom.get_format_data(name="format_es_url")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_es_url, message="Enterprise Security URL", name="es_url", pin_style="grey", pin_type="card")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def format_es_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_es_note() called")

    ################################################################################
    # Format a note with the current event information.
    ################################################################################

    template = """SOAR event created: {0}\nComplete details can be found here: {1}/analyst/timeline\n\nClosing Notable with confirmed receipt"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_note", scope="all")

    update_notable(container=container)

    return


@phantom.playbook_block()
def update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Update the notable event  in Enterprise Security with a link back to this container
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"], scope="all")
    format_es_note = phantom.get_format_data(name="format_es_note")

    parameters = []

    # build parameters list for 'update_notable' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "status": "closed",
                "comment": format_es_note,
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

    phantom.act("update event", parameters=parameters, name="update_notable", assets=["splunkes"])

    return


@phantom.playbook_block()
def format_event_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_event_name() called")

    ################################################################################
    # Format the event name as 'Source: Risk Object'
    ################################################################################

    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.source"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_event_name", scope="all", drop_none=True)

    container_update_info(container=container)

    return


@phantom.playbook_block()
def container_update_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("container_update_info() called")

    id_value = container.get("id", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.urgency","artifact:*.cef.source","artifact:*.id"], scope="all")
    format_event_name = phantom.get_format_data(name="format_event_name")

    parameters = []

    # build parameters list for 'container_update_info' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "name": format_event_name,
            "tags": None,
            "label": None,
            "owner": None,
            "status": None,
            "severity": container_artifact_item[0],
            "input_json": None,
            "description": container_artifact_item[1],
            "sensitivity": None,
            "container_input": id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_info", callback=artifact_update_severity)

    return


@phantom.playbook_block()
def artifact_update_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_update_severity() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'artifact_update_severity' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": container_artifact_item[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_severity")

    return


@phantom.playbook_block()
def format_multi_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_multi_urls() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.urls"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_multi_urls", drop_none=True)

    multi_urls_exist(container=container)

    return


@phantom.playbook_block()
def multi_urls_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("multi_urls_exist() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["format_multi_urls:formatted_data", "!=", None]
        ],
        name="multi_urls_exist:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        clean_url_code(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def clean_url_code(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("clean_url_code() called")

    format_multi_urls = phantom.get_format_data(name="format_multi_urls")

    clean_url_code__url_string = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    def clean(clean_string):
        if clean_string == None or len(clean_string) == 0:
            phantom.debug("Nothing detected in urls!")
            return clean_string
        else:
            phantom.debug("before clean {}".format(clean_string))
            clean_string = clean_string.replace("[", "")
            clean_string = clean_string.replace("]", "")
            clean_string = clean_string.replace("'", "")             
            phantom.debug("after clean {}".format(clean_string))
            return clean_string
            

    phantom.debug(format_multi_urls)
    clean_url_code__url_string = clean(format_multi_urls)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="clean_url_code:url_string", value=json.dumps(clean_url_code__url_string))

    urls_split(container=container)

    return


@phantom.playbook_block()
def urls_split(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("urls_split() called")

    clean_url_code__url_string = json.loads(_ if (_ := phantom.get_run_data(key="clean_url_code:url_string")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "delimiter": ",",
        "input_string": clean_url_code__url_string,
        "strip_whitespace": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/string_split", parameters=parameters, name="urls_split", callback=create_url_artifacts)

    return


@phantom.playbook_block()
def create_url_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_url_artifacts() called")

    id_value = container.get("id", None)
    urls_split_data = phantom.collect2(container=container, datapath=["urls_split:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'create_url_artifacts' call
    for urls_split_data_item in urls_split_data:
        parameters.append({
            "name": "url",
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": "artifact_url",
            "cef_value": urls_split_data_item[0],
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

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_url_artifacts")

    return


@phantom.playbook_block()
def format_single_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_single_url() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_single_url", drop_none=True)

    single_url_exists(container=container)

    return


@phantom.playbook_block()
def single_url_exists(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("single_url_exists() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["format_single_url:formatted_data", "!=", None]
        ],
        name="single_url_exists:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        clean_url_code_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def clean_url_code_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("clean_url_code_1() called")

    format_single_url = phantom.get_format_data(name="format_single_url")

    clean_url_code_1__url_string = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    def clean(clean_string):
        if clean_string == None or len(clean_string) == 0:
            phantom.debug("Nothing detected in urls!")
            return clean_string
        else:
            phantom.debug("before clean {}".format(clean_string))
            clean_string = clean_string.replace("[", "")
            clean_string = clean_string.replace("]", "")
            clean_string = clean_string.replace("'", "")             
            phantom.debug("after clean {}".format(clean_string))
            return clean_string
            

    phantom.debug(format_single_url)
    clean_url_code_1__url_string = clean(format_single_url)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="clean_url_code_1:url_string", value=json.dumps(clean_url_code_1__url_string))

    artifact_create_9(container=container)

    return


@phantom.playbook_block()
def artifact_create_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create_9() called")

    id_value = container.get("id", None)
    clean_url_code_1__url_string = json.loads(_ if (_ := phantom.get_run_data(key="clean_url_code_1:url_string")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "name": "domain",
        "tags": None,
        "label": None,
        "severity": None,
        "cef_field": "artifact_domain",
        "cef_value": clean_url_code_1__url_string,
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

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_9")

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