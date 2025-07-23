"""
This playbook will install the Splunk Universal Forwarder on either Linux or Windows machines.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'join_pull_script_3' block
    join_pull_script_3(container=container)
    # call 'artifact_filter' block
    artifact_filter(container=container)

    return

@phantom.playbook_block()
def os_type_filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("os_type_filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.OS", "==", "Linux"]
        ],
        name="os_type_filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pull_script(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.OS", "==", "Windows"]
        ],
        name="os_type_filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_pull_script_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def pull_script(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pull_script() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    file_path_formatted_string = phantom.format(
        container=container,
        template="""/tmp/rhel/scipt_rhel.sh\n""",
        parameters=[
            ""
        ])

    parameters = []

    if file_path_formatted_string is not None:
        parameters.append({
            "file_path": file_path_formatted_string,
            "ip_hostname": "127.0.0.1",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="pull_script", assets=["test123"], callback=script_vault_id_2)

    return


@phantom.playbook_block()
def join_pull_script_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_pull_script_3() called")

    # call connected block "pull_script_3"
    pull_script_3(container=container, handle=handle)

    return


@phantom.playbook_block()
def pull_script_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pull_script_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "file_path": "/tmp/win/script_win.ps1s",
        "ip_hostname": "127.0.0.1",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="pull_script_3", assets=["test123"], callback=script_vault_id_3)

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

    phantom.add_note(container=container, content="Splunk Universal Forwarder command to install the agent has been executed.", note_format="markdown", note_type="general", title="Splunk Universal Forwarder")

    join_playbook_container_resolution_1(container=container)

    return


@phantom.playbook_block()
def update_es_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_es_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Splunk Universal Forwarder command to install the agent has been executed.\n\nAgent Version: {0}\nAgent Status: {1}\n""",
        parameters=[
            "agent_status:action_result.data.*.output",
            "agent_status:action_result.data.*.output"
        ])

    agent_status_result_data = phantom.collect2(container=container, datapath=["agent_status:action_result.data.*.output","agent_status:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_es_notable' call
    for agent_status_result_item in agent_status_result_data:
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

    phantom.act("update event", parameters=parameters, name="update_es_notable", assets=["splunkes"], callback=join_update_artifact_3)

    return


@phantom.playbook_block()
def join_playbook_container_resolution_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_playbook_container_resolution_1() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_playbook_container_resolution_1_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_playbook_container_resolution_1_called", value="playbook_container_resolution_1")

    # call connected block "playbook_container_resolution_1"
    playbook_container_resolution_1(container=container, handle=handle)

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
def check_approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_approval() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.status_label", "==", "Approved"]
        ],
        name="check_approval:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        os_type_filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.status_label", "!=", "Approved"]
        ],
        name="check_approval:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        update_es_notable_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def update_es_notable_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_es_notable_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Current status of the notable is not acceptable. Please seek approval and have the Remediation Approved status set before running any of the endpoint agent playbooks.""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_es_notable_1' call
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

    phantom.act("update event", parameters=parameters, name="update_es_notable_1", assets=["splunkes"], callback=update_artifact_2)

    return


@phantom.playbook_block()
def put_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("put_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'put_file' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "vault_id": "vault_id",
                "ip_hostname": container_artifact_item[0],
                "file_destination": "/root/",
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("put file", parameters=parameters, name="put_file", assets=["test123"], callback=download_installer)

    return


@phantom.playbook_block()
def download_installer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("download_installer() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""bash script_rhel.sh agent_download /tmp/""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'download_installer' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": command_formatted_string,
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

    phantom.act("execute program", parameters=parameters, name="download_installer", assets=["test123"], callback=install_agent)

    return


@phantom.playbook_block()
def install_agent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("install_agent() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""bash script_rhel.sh agent_install /tmp/""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'install_agent' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": command_formatted_string,
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

    phantom.act("execute program", parameters=parameters, name="install_agent", assets=["test123"], callback=agent_status)

    return


@phantom.playbook_block()
def delete_installer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_installer() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""rm -rf /tmp/script_installer/""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'delete_installer' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": command_formatted_string,
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

    phantom.act("execute program", parameters=parameters, name="delete_installer", assets=["test123"], callback=update_es_notable)

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
        check_approval(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
        pass

    return


@phantom.playbook_block()
def agent_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("agent_status() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""bash script_rhel.sh agent_status /tmp/""",
        parameters=[
            ""
        ])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'agent_status' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "command": command_formatted_string,
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

    phantom.act("execute program", parameters=parameters, name="agent_status", assets=["test123"], callback=delete_installer)

    return


@phantom.playbook_block()
def update_artifact_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_artifact_2() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_artifact_2' call
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

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="update_artifact_2", callback=join_playbook_container_resolution_1)

    return


@phantom.playbook_block()
def script_vault_id_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("script_vault_id_2() called")

    parameters = []

    parameters.append({
        "vault_id": None,
        "file_name": "script_rhel.sh",
        "container_id": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/vault_list", parameters=parameters, name="script_vault_id_2", callback=put_file)

    return


@phantom.playbook_block()
def script_vault_id_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("script_vault_id_3() called")

    parameters = []

    parameters.append({
        "vault_id": None,
        "file_name": "scipt_win.ps1s",
        "container_id": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/vault_list", parameters=parameters, name="script_vault_id_3", callback=create_folder)

    return


@phantom.playbook_block()
def create_folder(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_folder() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'create_folder' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "command": "mkdir \"C:\\Temp\\SOAR\"",
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

    phantom.act("run command", parameters=parameters, name="create_folder", assets=["abc"], callback=put_file_3)

    return


@phantom.playbook_block()
def put_file_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("put_file_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    pull_script_3_result_data = phantom.collect2(container=container, datapath=["pull_script_3:action_result.summary.vault_id","pull_script_3:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'put_file_3' call
    for pull_script_3_result_item in pull_script_3_result_data:
        for container_artifact_item in container_artifact_data:
            if pull_script_3_result_item[0] is not None:
                parameters.append({
                    "vault_id": pull_script_3_result_item[0],
                    "destination": "C:\\Temp\\SOAR\\script_win.ps1",
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

    phantom.act("upload file", parameters=parameters, name="put_file_3", assets=["abc"], callback=download_installer_3)

    return


@phantom.playbook_block()
def download_installer_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("download_installer_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""cd \"C:\\Temp\\SOAR\"; .\\script_win.ps1 agent_download""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'download_installer_3' call
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

    phantom.act("run script", parameters=parameters, name="download_installer_3", assets=["abc"], callback=install_agent_3)

    return


@phantom.playbook_block()
def install_agent_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("install_agent_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""cd \"C:\\Temp\\SOAR\"; .\\script_win.ps1 agent_install""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'install_agent_3' call
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

    phantom.act("run script", parameters=parameters, name="install_agent_3", assets=["abc"], callback=agent_status_3)

    return


@phantom.playbook_block()
def agent_status_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("agent_status_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""cd \"C:\\Temp\\SOAR\"; .\\script_win.ps1 agent_status""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'agent_status_3' call
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

    phantom.act("run script", parameters=parameters, name="agent_status_3", assets=["abc"], callback=delete_installer_3)

    return


@phantom.playbook_block()
def delete_installer_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_installer_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    script_str_formatted_string = phantom.format(
        container=container,
        template="""Remove-Item -Path \"C:\\Temp\\SOAR\" -Recurse -Force""",
        parameters=[])

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.IP","artifact:*.id"])

    parameters = []

    # build parameters list for 'delete_installer_3' call
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

    phantom.act("run script", parameters=parameters, name="delete_installer_3", assets=["abc"], callback=update_es_notable_4)

    return


@phantom.playbook_block()
def update_es_notable_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_es_notable_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Splunk Universal Forwarder command to install the agent has been executed.\n\nAgent Version: {0}\nAgent Status: {1}""",
        parameters=[
            "agent_version_3:action_result.data.*.std_out",
            "agent_status_3:action_result.data.*.std_out"
        ])

    agent_version_3_result_data = phantom.collect2(container=container, datapath=["agent_version_3:action_result.data.*.std_out","agent_version_3:action_result.parameter.context.artifact_id"], action_results=results)
    agent_status_3_result_data = phantom.collect2(container=container, datapath=["agent_status_3:action_result.data.*.std_out","agent_status_3:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_es_notable_4' call
    for agent_version_3_result_item in agent_version_3_result_data:
        for agent_status_3_result_item in agent_status_3_result_data:
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

    phantom.act("update event", parameters=parameters, name="update_es_notable_4", assets=["splunkes"], callback=join_update_artifact_3)

    return


@phantom.playbook_block()
def join_update_artifact_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_update_artifact_3() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_update_artifact_3_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_update_artifact_3_called", value="update_artifact_3")

    # call connected block "update_artifact_3"
    update_artifact_3(container=container, handle=handle)

    return


@phantom.playbook_block()
def update_artifact_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_artifact_3() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"])

    parameters = []

    # build parameters list for 'update_artifact_3' call
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

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="update_artifact_3", callback=add_container_note)

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