"""
Searches ServiceNow for incidents or changes related to the notable event
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_notable_id' block
    get_notable_id(container=container)

    return

@phantom.playbook_block()
def filter_tickets_and_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_tickets_and_list() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filter_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            ""
        ])

    parameters = []

    parameters.append({
        "table": "incident",
        "max_results": 100,
        "filter": filter_formatted_string,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list tickets", parameters=parameters, name="filter_tickets_and_list", assets=["test snow"], callback=get_results)

    return


@phantom.playbook_block()
def get_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_results() called")

    template = """{0}\n"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="get_results")

    format_es_update(container=container)

    return


@phantom.playbook_block()
def get_notable_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_notable_id() called")

    template = """{0}\n"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="get_notable_id", drop_none=True)

    filter_tickets_and_list(container=container)

    return


@phantom.playbook_block()
def add_findings_to_es_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_findings_to_es_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_notable_id = phantom.get_format_data(name="get_notable_id")
    format_es_update = phantom.get_format_data(name="format_es_update")

    parameters = []

    if get_notable_id is not None:
        parameters.append({
            "event_ids": get_notable_id,
            "comment": format_es_update,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="add_findings_to_es_notable", assets=["splunkes"])

    return


@phantom.playbook_block()
def format_es_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_es_update() called")

    template = """{0}\n"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_update", drop_none=True)

    add_findings_to_es_notable(container=container)

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