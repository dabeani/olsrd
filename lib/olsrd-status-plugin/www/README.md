Glyphicons and plugin fonts

This `www` folder provides the static web UI for the `olsrd-status-plugin`.

History / problem
- Older versions shipped the Bootstrap 3 `glyphicons-halflings-regular.*` font files under `www/fonts/`.
- Those font files are not present in this checkout. The packaging scripts (`cp_x86.sh`, `cp_arm64.sh`) historically attempted to copy them into the docker image and would fail if they were missing.

Current status
- The UI in `index.html` and the minimal `bootstrap.min.css` included with the plugin reference Bootstrap glyphicons (used for small UI icons). However, the CSS bundled here is a minimal subset and the site will still render fine using system fonts and Unicode fallback if glyphicons are missing.

Options to restore icons
1) Restore the original Glyphicons from Bootstrap 3
   - Download Bootstrap 3 (or just the `glyphicons-halflings-regular.*` files) and place them into `lib/olsrd-status-plugin/www/fonts/`.
   - Files expected (examples):
     - glyphicons-halflings-regular.eot
     - glyphicons-halflings-regular.svg
     - glyphicons-halflings-regular.ttf
     - glyphicons-halflings-regular.woff
     - glyphicons-halflings-regular.woff2
    - Direct download links (Bootstrap 3.4.1 release):
       - https://raw.githubusercontent.com/twbs/bootstrap/v3.4.1/dist/fonts/glyphicons-halflings-regular.eot
       - https://raw.githubusercontent.com/twbs/bootstrap/v3.4.1/dist/fonts/glyphicons-halflings-regular.svg
       - https://raw.githubusercontent.com/twbs/bootstrap/v3.4.1/dist/fonts/glyphicons-halflings-regular.ttf
       - https://raw.githubusercontent.com/twbs/bootstrap/v3.4.1/dist/fonts/glyphicons-halflings-regular.woff
       - https://raw.githubusercontent.com/twbs/bootstrap/v3.4.1/dist/fonts/glyphicons-halflings-regular.woff2

2) Use Font Awesome or another icon font instead
   - Edit `index.html` and `css/bootstrap.min.css` to include the desired icon CSS and update HTML markup if necessary.

3) Remove references to glyphicons
   - Change markup to use inline SVGs or Unicode symbols where icons are non-essential.

Packaging note
- The repository scripts `cp_x86.sh` and `cp_arm64.sh` have been updated to skip missing font files instead of failing. Packaging will continue without fonts; you will see console messages like:
  [info] Skipping missing file: lib/olsrd-status-plugin/www/fonts/glyphicons-halflings-regular.woff

If you want, I can add the missing font files to the repository (licensed under Bootstrap v3's SIL OFL / MIT combo) or switch the UI to use Font Awesome. Tell me which approach you prefer.
