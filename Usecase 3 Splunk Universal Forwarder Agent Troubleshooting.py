"""
This playbook is to troubleshoot a Splunk universal forwarder.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'artifact_filter' block
    artifact_filter(container=container)

    return

@phantom.playbook_block()
def telnet_hf_on_9997(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("telnet_hf_on_9997() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'telnet_hf_on_9997' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": "echo \"quit\" | telnet 1.2.3.4 9997",
                "ip_hostname": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="telnet_hf_on_9997", assets=["test123"], callback=agent_status_linux)

    return


@phantom.playbook_block()
def telnet_ds_on_8089(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("telnet_ds_on_8089() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'telnet_ds_on_8089' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": "echo \"quit\" | telnet 1.2.3.4 8089",
                "ip_hostname": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="telnet_ds_on_8089", assets=["test123"], callback=telnet_hf_on_9997)

    return


@phantom.playbook_block()
def agent_status_linux(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("agent_status_linux() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'agent_status_linux' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": "/opt/splunkforwarder/bin/splunk status",
                "ip_hostname": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="agent_status_linux", assets=["test123"], callback=format_summary_for_linux)

    return


@phantom.playbook_block()
def netconnect_to_ds_on_8089(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("netconnect_to_ds_on_8089() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""test-netconnection 1.2.3.4 -port 8089\n""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'netconnect_to_ds_on_8089' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "script_str": script_str_formatted_string,
            "ip_hostname": container_artifact_item[0],
            "context": {'artifact_id': container_artifact_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="netconnect_to_ds_on_8089", assets=["abc"], callback=netconnect_to_hf_on_9997)

    return


@phantom.playbook_block()
def netconnect_to_hf_on_9997(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("netconnect_to_hf_on_9997() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""test-netconnection 1.2.3.4 -port 9997""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'netconnect_to_hf_on_9997' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "script_str": script_str_formatted_string,
            "ip_hostname": container_artifact_item[0],
            "context": {'artifact_id': container_artifact_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="netconnect_to_hf_on_9997", assets=["abc"], callback=agent_status_windows)

    return


@phantom.playbook_block()
def agent_status_windows(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("agent_status_windows() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""cd \"C:\\Program Files\\SplunkUniversalForwarder\\bin\\\"; .\\splunk status\n""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'agent_status_windows' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "script_str": script_str_formatted_string,
            "ip_hostname": container_artifact_item[0],
            "context": {'artifact_id': container_artifact_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run script", parameters=parameters, name="agent_status_windows", assets=["abc"], callback=format_summary_for_windows)

    return


@phantom.playbook_block()
def os_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("os_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.OS", "==", "Windows"]
        ],
        name="os_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        netconnect_to_ds_on_8089(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.OS", "==", "Linux"]
        ],
        name="os_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        telnet_ds_on_8089(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def join_add_container_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_add_container_note() called")

    if phantom.completed(action_names=["update_notable", "update_notable_1"]):
        # call connected block "add_container_note"
        add_container_note(container=container, handle=handle)

    return


@phantom.playbook_block()
def add_container_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_container_note() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content="Splunk Universal Forwarder troubleshooting commands have been executed.", note_format="markdown", note_type="general", title="Splunk Universal Forwarder")

    playbook_container_resolution_1(container=container)

    return


@phantom.playbook_block()
def update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""{0}""",
        parameters=[
            "format_summary_for_linux:formatted_data"
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    format_summary_for_linux = phantom.get_format_data(name="format_summary_for_linux")

    parameters = []

    # build parameters list for 'update_notable' call
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

    phantom.act("update event", parameters=parameters, name="update_notable", assets=["splunkes"], callback=join_add_container_note)

    return


@phantom.playbook_block()
def playbook_container_resolution_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_container_resolution_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "soar-h3/Container Resolution", returns the playbook_run_id
    playbook_run_id = phantom.playbook("soar-h3/Container Resolution", container=container)

    return


@phantom.playbook_block()
def format_summary_for_linux(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_summary_for_linux() called")

    ################################################################################
    # Gathers all results from commands into a more readable output for ES
    ################################################################################

    template = """Telnet to Deployment Server Result\n{1}\n\nTelnet to Heavy Forwarder Result\n{2}\n\nAgent Status Result\n{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "agent_status_linux:action_result.data.*.output",
        "telnet_ds_on_8089:action_result.data.*.output",
        "telnet_hf_on_9997:action_result.data.*.output"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_summary_for_linux", drop_none=True)

    update_artifact(container=container)

    return


@phantom.playbook_block()
def format_summary_for_windows(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_summary_for_windows() called")

    template = """Telnet to Deployment Server Result\n{1}\n\nTelnet to Heavy Forwarder Result\n{2}\n\nAgent Status Result\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "agent_status_windows:action_result.data.*.std_out",
        "netconnect_to_ds_on_8089:action_result.data.*.std_out",
        "netconnect_to_hf_on_9997:action_result.data.*.std_out"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_summary_for_windows", drop_none=True)

    update_artifact_1(container=container)

    return


@phantom.playbook_block()
def artifact_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.artifact_status", "==", "old_artifact"]
        ],
        name="artifact_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.artifact_status", "==", ""]
        ],
        name="artifact_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        os_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def update_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_artifact() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_artifact' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": "artifact_status",
            "cef_value": "old_artifact",
            "input_json": None,
            "artifact_id": container_artifact_item[0],
            "cef_data_type": None,
            "overwrite_tags": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="update_artifact", callback=update_notable)

    return


@phantom.playbook_block()
def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_artifact_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_artifact_1' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": "artifact_status",
            "cef_value": "old_artifact",
            "input_json": None,
            "artifact_id": container_artifact_item[0],
            "cef_data_type": None,
            "overwrite_tags": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="update_artifact_1", callback=update_notable_1)

    return


@phantom.playbook_block()
def update_notable_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_notable_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    format_summary_for_windows = phantom.get_format_data(name="format_summary_for_windows")

    parameters = []

    # build parameters list for 'update_notable_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "comment": format_summary_for_windows,
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

    phantom.act("update event", parameters=parameters, name="update_notable_1", assets=["splunkes"], callback=join_add_container_note)

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