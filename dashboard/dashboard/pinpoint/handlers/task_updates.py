# Copyright 2019 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import base64
import binascii
import json
import logging
import webapp2

from dashboard.pinpoint.models import job as job_module
from dashboard.pinpoint.models import task as task_module
from dashboard.pinpoint.models import event as event_module
from dashboard.pinpoint.models.tasks import evaluator


def HandleTaskUpdate(request_body):
  # Read the JSON body of the message, as how Pub/Sub will use.
  try:
    body = json.loads(request_body)
  except ValueError as error:
    raise ValueError('Failed JSON parsing request body: %s (%s)' %
                     (error, request_body[:40] + '...'))

  message = body.get('message')
  if not message:
    raise ValueError('Cannot find `message` in the request: %s' % (body,))

  # Load the base64-encoded data in the message, which should include the
  # following information:
  #   - job id
  #   - task id
  #   - additional task-specific details
  data = message.get('data', '')
  if not data:
    raise ValueError('Missing data field in `message`: %s' % (message,))

  try:
    decoded_data = base64.urlsafe_b64decode(data.encode('utf-8'))
  except TypeError as error:
    raise ValueError('Failed decoding `data` field in `message`: %s (%s)' %
                     (error, data))

  try:
    swarming_data = json.loads(decoded_data)
  except ValueError as error:
    raise ValueError('Failed JSON parsing `data` field in `message`: %s (%s)' %
                     (error, data))
  logging.debug('Received: %s', swarming_data)

  # From the swarming data, we can determine the job id and task id (if
  # there's any) which we can handle appropriately. Swarming will send a
  # message of the form:
  #
  #   {
  #     "task_id": <swarming task id>
  #     "userdata": <base64 encoded data>
  #   }
  #
  # In the 'userdata' field we can then use details to use the execution
  # engine, if the job is meant to be executed with the engine.
  userdata = swarming_data.get('userdata')
  if not userdata:
    raise ValueError('Ill-formed swarming update: %s' % (swarming_data,))

  pinpoint_data = json.loads(userdata)
  job_id = pinpoint_data.get('job_id')
  if not job_id:
    raise ValueError('Missing job_id from pinpoint data.')

  job = job_module.JobFromId(job_id)
  if not job:
    raise ValueError('Failed to find job with ID = %s' % (job_id,))

  # If we're not meant to use the execution engine, bail out early.
  if not job.use_execution_engine:
    return

  task_data = pinpoint_data.get('task')
  if not task_data:
    raise ValueError('Missing "task" field in the payload')

  # For build events, we follow the convention used by the evaluators that
  # react to build events.
  event = None
  task_type = task_data.get('type')
  task_id = task_data.get('id')
  payload = {}
  if task_type == 'build':
    payload = {'status': 'build_completed'}
  event = event_module.Event(
      type='update', target_task=task_id, payload=payload)

  # From here, we have enough information to evaluate the task graph.
  try:
    accumulator = task_module.Evaluate(job, event,
                                       evaluator.ExecutionEngine(job))

    # Then decide to update the Job if we find a terminal state from the
    # root 'find_culprit' node.
    if 'performance_bisection' not in accumulator:
      raise ValueError(
          'Missing "performance_bisection" in task graph for job with ID = %s' %
          (job_id,))

    result_status = accumulator['performance_bisection']['status']
    if result_status in {'failed', 'completed'}:
      # TODO(dberris): Formalise the error collection/propagation mechanism
      # for exposing all errors in the UX, when we need it.
      execution_errors = accumulator['performance_bisection'].get('errors', [])
      if execution_errors:
        job.exception_details = execution_errors[0]
      job._Complete()

  except task_module.Error as error:
    logging.error('Failed: %s', error)
    job.Fail()
    job.put()
    raise


class TaskUpdates(webapp2.RequestHandler):
  """Handle updates received from Pub/Sub on Swarming Tasks."""

  def post(self):
    """Handle push messages including information about the swarming task."""
    try:
      HandleTaskUpdate(self.request.body)
    except (ValueError, binascii.Error) as error:
      logging.error('Failed: %s', error)

    self.response.status = 204
    self.response.write('')
