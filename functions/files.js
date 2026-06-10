export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  url.pathname = '/files.html';
  return env.ASSETS.fetch(new Request(url.toString(), request));
}
