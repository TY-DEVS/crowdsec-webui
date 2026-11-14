import type {
  BulkDeleteRequest,
  UpsertNotificationChannelRequest,
  UpsertNotificationRuleRequest,
} from '../../../shared/contracts';
import type { ApiRouteDependencies } from '../api-routes';

export function registerNotificationRoutes(dependencies: ApiRouteDependencies): void {
  const {
    app,
    config,
    ensureAuth,
    ensureCanManageSettings,
    getPageRequest,
    normalizeNotificationIds,
    notificationService,
  } = dependencies;

  app.get(`${config.basePath}/api/notifications`, ensureAuth, (context) => {
    const pageRequest = getPageRequest(context) || { page: 1, pageSize: 50 };
    return context.json(notificationService.listNotifications(pageRequest.page, pageRequest.pageSize));
  });

  app.post(`${config.basePath}/api/notifications/:id/read`, ensureAuth, async (context) => {
    const id = String(context.req.param('id'));
    const updated = await notificationService.markNotificationRead(id);
    if (!updated) {
      return context.json({ error: 'Notification not found' }, 404);
    }
    return context.json({ success: true });
  });

  app.post(`${config.basePath}/api/notifications/bulk-read`, ensureAuth, async (context) => {
    const body = await context.req.json<BulkDeleteRequest>();
    const ids = normalizeNotificationIds(body.ids);
    if (ids.length === 0) {
      return context.json({ error: 'At least one notification ID is required' }, 400);
    }

    return context.json({ updated: await notificationService.markNotificationsRead(ids) });
  });

  app.post(`${config.basePath}/api/notifications/bulk-delete`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    const body = await context.req.json<BulkDeleteRequest>();
    const ids = normalizeNotificationIds(body.ids);
    if (ids.length === 0) {
      return context.json({ error: 'At least one notification ID is required' }, 400);
    }

    return context.json({ deleted: await notificationService.deleteNotifications(ids) });
  });

  app.post(`${config.basePath}/api/notifications/delete-read`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    return Response.json({ deleted: await notificationService.deleteReadNotifications() });
  });

  app.delete(`${config.basePath}/api/notifications/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    const id = String(context.req.param('id'));
    if (!await notificationService.deleteNotification(id)) {
      return context.json({ error: 'Notification not found' }, 404);
    }

    return context.json({ success: true });
  });

  app.get(`${config.basePath}/api/notifications/settings`, ensureAuth, () => Response.json(notificationService.listSettings()));

  app.post(`${config.basePath}/api/notification-channels`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const body = await context.req.json<UpsertNotificationChannelRequest>();
      return context.json(await notificationService.createChannel(body), 201);
    } catch (error: any) {
      return context.json({ error: error.message || 'Failed to create notification channel' }, 400);
    }
  });

  app.put(`${config.basePath}/api/notification-channels/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const id = String(context.req.param('id'));
      const body = await context.req.json<UpsertNotificationChannelRequest>();
      return context.json(await notificationService.updateChannel(id, body));
    } catch (error: any) {
      const status = error.message === 'Notification channel not found' ? 404 : 400;
      return context.json({ error: error.message || 'Failed to update notification channel' }, status);
    }
  });

  app.delete(`${config.basePath}/api/notification-channels/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    const id = String(context.req.param('id'));
    await notificationService.deleteChannel(id);
    return context.json({ success: true });
  });

  app.post(`${config.basePath}/api/notification-channels/:id/test`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const id = String(context.req.param('id'));
      return context.json(await notificationService.testChannel(id));
    } catch (error: any) {
      const status = error.message === 'Notification channel not found' ? 404 : 400;
      return context.json({ error: error.message || 'Failed to send test notification' }, status);
    }
  });

  app.post(`${config.basePath}/api/notification-rules`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const body = await context.req.json<UpsertNotificationRuleRequest>();
      return context.json(await notificationService.createRule(body), 201);
    } catch (error: any) {
      return context.json({ error: error.message || 'Failed to create notification rule' }, 400);
    }
  });

  app.put(`${config.basePath}/api/notification-rules/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const id = String(context.req.param('id'));
      const body = await context.req.json<UpsertNotificationRuleRequest>();
      return context.json(await notificationService.updateRule(id, body));
    } catch (error: any) {
      const status = error.message === 'Notification rule not found' ? 404 : 400;
      return context.json({ error: error.message || 'Failed to update notification rule' }, status);
    }
  });

  app.post(`${config.basePath}/api/notification-rules/:id/test`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const id = String(context.req.param('id'));
      return context.json(await notificationService.testRule(id));
    } catch (error: any) {
      const status = error.message === 'Notification rule not found' ? 404 : 400;
      return context.json({ error: error.message || 'Failed to send rule test' }, status);
    }
  });

  app.delete(`${config.basePath}/api/notification-rules/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    const id = String(context.req.param('id'));
    await notificationService.deleteRule(id);
    return context.json({ success: true });
  });
}
