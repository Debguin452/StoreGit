export async function onRequest({ request, env }) {
  if (env.ASSETS) {
    const url = new URL(request.url);
    url.pathname = '/files.html';
    return env.ASSETS.fetch(url.toString());
  }
  return Response.redirect(new URL(request.url).origin + '/', 302);
}
