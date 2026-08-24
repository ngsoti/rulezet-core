"""
notifications.py — opt-in email alerts for the Admin Task Scheduler,
configured per workflow (AdminWorkflow.notify_on_failure/notify_on_success/
notify_emails), not per task: one place to turn emails on/off for an entire
pipeline. Reuses the app's existing, already-working mail pattern (see
app/features/account/account_core.py's send_verify_email) rather than
inventing a new one.
"""
from flask_mail import Message

from app import mail


def maybe_send_task_alert(workflow, task, job):
    """Called from scheduler_engine.on_job_finished() right after a
    STANDALONE task's (not part of a workflow launch) final status is known.
    Sends nothing if the workflow opted out of that kind of alert. A task
    that's part of a "Run Workflow" launch instead gets exactly one email
    for the whole launch — see maybe_send_workflow_run_alert below — so an
    admin isn't emailed once per task in a multi-task pipeline."""
    kind = 'success' if job.status == 'done' else 'failure'
    if kind == 'failure' and not workflow.notify_on_failure:
        return
    if kind == 'success' and not workflow.notify_on_success:
        return

    recipients = []
    if workflow.editor and workflow.editor.email:
        recipients.append(workflow.editor.email)
    recipients.extend(workflow.notify_emails or [])
    if not recipients:
        return

    status_color = '#198754' if kind == 'success' else '#dc3545'
    status_label = 'succeeded' if kind == 'success' else 'failed'
    subject = f"[Rulezet] Task '{task.title}' {status_label} — workflow '{workflow.title}'"

    error_html = ''
    if kind == 'failure' and job.error:
        error_html = f"""
                <div style="margin-top:16px;padding:14px 16px;background:#fdf2f2;border:1px solid #f5c6cb;border-radius:8px;">
                    <p style="margin:0;font-size:13px;color:#721c24;font-family:monospace;white-space:pre-wrap;">{job.error}</p>
                </div>"""

    try:
        msg = Message(subject, recipients=recipients)
        msg.html = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #eeeeee; border-radius: 12px; overflow: hidden;">
            <div style="background-color: #2c3e50; padding: 24px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 20px;">Workflow task {status_label}</h1>
            </div>
            <div style="padding: 30px; line-height: 1.6; color: #333333; background-color: #ffffff;">
                <p style="font-size: 15px;">
                    Workflow <strong>"{workflow.title}"</strong> —
                    <span style="color:{status_color};font-weight:bold;">{status_label}</span>
                </p>
                <p style="font-size: 15px;">Task: <strong>{task.title}</strong></p>
                <p style="font-size: 13px; color: #7f8c8d;">Job type: {job.job_type}</p>
                {error_html}
                <div style="text-align:center;margin-top:24px;">
                    <a href="/admin/tasks/?workflow={workflow.uuid}"
                       style="display:inline-block;padding:10px 24px;background:#0d6efd;color:#ffffff;text-decoration:none;border-radius:6px;font-size:14px;">
                        View workflow
                    </a>
                </div>
            </div>
            <div style="background-color: #f8f9fa; padding: 16px; text-align: center; font-size: 12px; color: #bdc3c7; border-top: 1px solid #eeeeee;">
                <p style="margin: 0;">You're receiving this because email alerts are enabled for this workflow.</p>
            </div>
        </div>
        """
        mail.send(msg)
    except Exception as e:
        print(f"[task_scheduler] failed to send task alert email: {e}")


def maybe_send_workflow_run_alert(workflow, kind, summary=None):
    """One email per "Run Workflow" launch lifecycle event — never per task —
    mirroring the in-app 'workflow run started/finished' bell notification.
    kind: 'started' | 'success' | 'failure'.

    'started' reuses notify_on_failure/notify_on_success as an implicit
    "alerts are wanted for this workflow at all" gate — there's no separate
    toggle for it, since a launch you don't want end-of-run alerts for isn't
    one you want a start alert for either."""
    if kind == 'failure' and not workflow.notify_on_failure:
        return
    if kind == 'success' and not workflow.notify_on_success:
        return
    if kind == 'started' and not (workflow.notify_on_failure or workflow.notify_on_success):
        return

    recipients = []
    if workflow.editor and workflow.editor.email:
        recipients.append(workflow.editor.email)
    recipients.extend(workflow.notify_emails or [])
    if not recipients:
        return

    labels = {'started': ('Workflow launched', '#0d6efd', 'launched'),
              'success': ('Workflow finished', '#198754', 'finished successfully'),
              'failure': ('Workflow finished', '#dc3545', 'finished with errors')}
    heading, color, status_label = labels[kind]
    subject = f"[Rulezet] Workflow \"{workflow.title}\" {status_label}"

    summary_html = f'<p style="font-size: 14px; color: #555;">{summary}</p>' if summary else ''

    try:
        msg = Message(subject, recipients=recipients)
        msg.html = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #eeeeee; border-radius: 12px; overflow: hidden;">
            <div style="background-color: #2c3e50; padding: 24px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 20px;">{heading}</h1>
            </div>
            <div style="padding: 30px; line-height: 1.6; color: #333333; background-color: #ffffff;">
                <p style="font-size: 15px;">
                    Workflow <strong>"{workflow.title}"</strong> —
                    <span style="color:{color};font-weight:bold;">{status_label}</span>
                </p>
                {summary_html}
                <div style="text-align:center;margin-top:24px;">
                    <a href="/admin/tasks/{workflow.uuid}"
                       style="display:inline-block;padding:10px 24px;background:#0d6efd;color:#ffffff;text-decoration:none;border-radius:6px;font-size:14px;">
                        View workflow
                    </a>
                </div>
            </div>
            <div style="background-color: #f8f9fa; padding: 16px; text-align: center; font-size: 12px; color: #bdc3c7; border-top: 1px solid #eeeeee;">
                <p style="margin: 0;">You're receiving this because email alerts are enabled for this workflow.</p>
            </div>
        </div>
        """
        mail.send(msg)
    except Exception as e:
        print(f"[task_scheduler] failed to send workflow run alert email: {e}")
