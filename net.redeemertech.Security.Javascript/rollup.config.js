/* eslint-disable */
const path = require("path");
const copy = require("rollup-plugin-copy");
const { defineConfigs } = require("../Rock/Rock.JavaScript.Obsidian/Build/build-tools");

const workspacePath = path.resolve(__dirname);
const srcPath = path.join(workspacePath, "src");
const outPath = path.join(workspacePath, "dist");
const blocksPath = path.join(workspacePath, "..", "Rock", "RockWeb", "Plugins", "net_redeemertech", "Security");
const assetSourcePath = "assets/**/*.js";

const configs = defineConfigs(srcPath, outPath, {
    copy: blocksPath
});

if (configs.length > 0) {
    configs[0].plugins.push(copy({
        targets: [
            {
                src: assetSourcePath,
                dest: outPath,
                flatten: false
            },
            {
                src: assetSourcePath,
                dest: blocksPath,
                flatten: false
            }
        ],
        hook: "writeBundle"
    }));
}

export default configs;
