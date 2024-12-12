"""
example of a playbook to run a search against splunk notable index to correlate other notables together if a common field was observed
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'notable_search' block
    notable_search(container=container)

    return

@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    notable_search = phantom.get_format_data(name="notable_search")

    parameters = []

    if notable_search is not None:
        parameters.append({
            "query": notable_search,
            "command": "search",
            "start_time": "",
            "search_mode": "smart",
            "attach_result": False,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunkes"], callback=format_results)

    return


@phantom.playbook_block()
def notable_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("notable_search() called")

    template = """`notable`\n| search (user IN ({0})) OR (src_ip IN ({1})) OR (dest_ip IN ({2})) OR (host IN ({3}))\n| eval rule_name=if(isnull(rule_name),source,rule_name)\n| eval rule_title=if(isnull(rule_title),rule_name,rule_title) \n| eval rule_description=if(isnull(rule_description),source,rule_description)\n| eval security_domain=if(isnull(security_domain),source,security_domain)\n| table owner, status, event_hash, event_id, rule_name"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.user",
        "artifact:*.cef.src_ip",
        "artifact:*.cef.dest_ip",
        "artifact:*.cef.host"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="notable_search", drop_none=True)

    run_query_1(container=container)

    return


@phantom.playbook_block()
def format_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_results() called")

    template = """The following notables have been found to be correlated with the same user, host, src_ip or dest_ip\n\n{0}\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_results", separator=", ", drop_none=True)

    add_note_2(container=container)
    paste_results_to_notable_event(container=container)

    return


@phantom.playbook_block()
def paste_results_to_notable_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("paste_results_to_notable_event() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])

    parameters = []

    # build parameters list for 'paste_results_to_notable_event' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
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

    phantom.act("update event", parameters=parameters, name="paste_results_to_notable_event", assets=["splunkes"])

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    format_results = phantom.get_format_data(name="format_results")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_results, note_format="markdown", note_type="general", title="search results")

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