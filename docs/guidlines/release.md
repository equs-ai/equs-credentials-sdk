# Publish a New Release

1. Create a new release tag.
    1. Verify that the demo application runs successfully and passes all flows.
    2. Verify that the latest commit in the main branch contains all changes to be included in the release.
    3. Verify that the version in the Cargo.toml and package.json files have changed.
        1. [ASDK Rust version (Main)](../../Cargo.toml)
        2. [ASDK Node.js version](../../wrappers/nodejs/package.json)
        3. [ASDK WASM version](../../wrappers/wasm/package.json)
        4. [ASDK Askar plugin](../../plugins/askar/wrappers/nodejs/package.json)
        5. [ASDK Android version](../../wrappers/uniffi/kotlin/android/build.gradle.kts)
        6. [ASDK IOS version](../../wrappers/uniffi/scripts/build_and_publish_ios.sh)
    4. Create a new tag for the release.
        - Using local terminal: replace <version> with the appropriate version number (e.g., 0.4.2):
             ```shell
             git tag <version>
             git push origin tag <version>
             ```
        - Using gitlab UI.
            - Go to `Code` -> `Tags` -> `New Tag`
2. Prepare the release in Gitlab.
    1. Access the Release Section:

    - Navigate to the ASDK GitLab repository.
    - From the left-hand menu, select Deploy → Release.

    2. Create a New Release:

    - Tap New release.
    - In the Tag name field, select the previously created release tag.
    - Provide a release title in the format: `ASDK {version}` (e.g., ASDK 0.4.2).

    3. Add Release Notes:
        - Use the following format for each note:
       ```text
       [feat|fix|chore] {Description}: [{Task number}]({Task link})
       ```
        - Example
       ```text
        - [feat] Enable setting of clock tolerance while building Issuer service: ASDK-311.
        - [fix] Correction of PoP validation error messages on the Holder side: ASDK-311.
        - [chore] Security Logging adjustments: ASDK-214
       ```
    4. Finalize and Publish:

    - Tap Create release to finalize the process.
3. Prepare a New Release Page.
    - Navigate to the ASDK Deliverables
      page: https://blockchains-inc.atlassian.net/wiki/spaces/SDKDSR/pages/183370275/Deliverables
    - Create a new page with the title format: `ASDK v{Version}, {Month} {Day}` (e.g., ASDK v0.4.2, Dec 4).
    - Provide Gitlab Links for:
        - Release and notes,
        - Demos.
        - Documentation.
    - API Changes: Provide details of changes module-wise.
    - Migration Guide (if applicable): Describe any required steps for migrating to the new release.
    - Next Plans: Outline the immediate goals or enhancements planned for the next release.
4. Announce release.
    - Inform DSR ASDK integration teams in Mattermost
    - Inform HTEC ASDK integration teams in MC Teams
