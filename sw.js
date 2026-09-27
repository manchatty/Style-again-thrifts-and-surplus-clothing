self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch(e) {}
  const title = data.title || 'STYLE AGAIN';
  const options = {
    body: data.body || 'You have a new store update.',
    
    
    data: { url: data.url || '/admin-dashboard.html' },
    vibrate: [200,100,200]
  };
  event.waitUntil(self.registration.showNotification(title, options));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/admin-dashboard.html';
  event.waitUntil(clients.matchAll({type:'window', includeUncontrolled:true}).then(list => {
    for (const client of list) { if ('focus' in client) { client.navigate(url); return client.focus(); } }
    return clients.openWindow(url);
  }));
});
