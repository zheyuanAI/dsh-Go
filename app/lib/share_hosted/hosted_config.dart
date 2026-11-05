// Where hosted conversation links live (docs/design/share-links.md). Same level
// as `shareLandingUrl` in share_code/share_link.dart: change the host here, in
// services/share-worker/wrangler.jsonc, and redeploy.

import '../services/site_service.dart' show siteServiceOrigin;

/// The share host (services/share-worker). A link is
/// `$shareHostOrigin/c/<id>#k=<key>`; the key never reaches the server.
const shareHostOrigin = siteServiceOrigin;

/// Persisted links from before the fork moved to Sites still name this host.
const legacyShareHostOrigin = 'https://go.dshtui.com';
