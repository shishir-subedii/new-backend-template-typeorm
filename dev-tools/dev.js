// dev-tools/dev.js
// Used to manage development environment: start/stop Docker services and Nest.js dev server
//Usage:
/*
pnpm dev start (Start Docker + Nest.js dev server)
pnpm dev start pull (Pull latest backend updates, install deps, then start)
pnpm dev stop (Stop Nest.js + Docker services)
Ctrl+C during start (Gracefully shutdown + clear terminal)
*/


const { execSync, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

function log(msg, color = "\x1b[36m") {
    console.log(color + msg + "\x1b[0m");
}

function run(cmd) {
    log(`\n> ${cmd}`, "\x1b[33m");
    execSync(cmd, { stdio: "inherit", cwd: PROJECT_ROOT, shell: true });
}

function checkCommand(cmd, name = cmd) {
    try {
        execSync(`${cmd} --version`, { stdio: "ignore", shell: true });
    } catch (e) {
        console.error(`❌ ${name} is not installed or not in PATH.`);
        process.exit(1);
    }
}

let childProcess = null;

function gracefulShutdown() {
    log("\n⚡ Shutting down services...", "\x1b[31m");

    try {
        log("Stopping Nest.js dev server...");
        if (childProcess) {
            childProcess.kill("SIGINT");
        }
    } catch (e) { }

    try {
        log("Stopping Docker services...");
        run("docker compose down"); // safe: does not remove named volumes
    } catch (e) { }

    // Clear the terminal after shutdown
    try {
        if (process.platform === "win32") {
            execSync("cls", { stdio: "inherit", shell: true });
        } else {
            execSync("clear", { stdio: "inherit", shell: true });
        }
    } catch (e) { }

    process.exit(0);
}


// Listen for Ctrl+C or other termination signals
process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);

async function main() {
    const arg1 = process.argv[2];
    const arg2 = process.argv[3];

    log("\n=== Dev Manager (Node CLI) ===\n", "\x1b[32m");

    // ------- CHECK REQUIREMENTS -------
    checkCommand("docker", "Docker");
    checkCommand("pnpm", "PNPM");
    checkCommand("git", "Git");

    // ------- CHECK DOCKER RUNNING -------
    try {
        execSync("docker info", { stdio: "ignore", shell: true });
    } catch (e) {
        console.error("❌ Docker Desktop is not running!");
        process.exit(1);
    }

    // ------- AUTO-CREATE .env -------
    const envPath = path.join(PROJECT_ROOT, ".env");
    const examplePath = path.join(PROJECT_ROOT, ".env.example");

    if (!fs.existsSync(envPath) && fs.existsSync(examplePath)) {
        fs.copyFileSync(examplePath, envPath);
        log("✔ Created .env from .env.example", "\x1b[32m");
    }

    // ------- COMMAND HANDLER -------
    if (arg1 === "start") {
        // ----- git pull + install -----
        if (arg2 === "pull") {
            // ----- check current branch -----
            const currentBranch = execSync("git rev-parse --abbrev-ref HEAD", {
                cwd: PROJECT_ROOT,
                encoding: "utf-8",
                shell: true,
            }).trim();

            log(`Current Git branch: ${currentBranch}`, "\x1b[35m");

            if (currentBranch !== "main") {
                console.error(
                    `\n❌ You are on branch '${currentBranch}'. You must be on 'main' to pull updates.\n` +
                    `Switch back using:\n\n` +
                    `    git switch main\n\n` +
                    `Then try again.\n`
                );
                process.exit(1);
            }

            const status = execSync("git status --porcelain", {
                cwd: PROJECT_ROOT,
                encoding: "utf-8",
                shell: true,
            }).trim();

            if (status.length > 0) {
                console.error(
                    "\n❌ Your repository has local changes. Reset everything:\n\n" +
                    "    git reset --hard HEAD\n\nThen run again.\n"
                );
                process.exit(1);
            }

            log("Pulling latest changes...", "\x1b[36m");
            run("git pull");

            log("Installing dependencies...", "\x1b[36m");
            run("pnpm install");
        }

        // ----- docker up -----
        log("Starting Docker services...");
        run("docker compose up -d");

        // ----- start Nest.js -----
        log("Starting Nest.js dev server...\n", "\x1b[32m");

        childProcess = spawn("pnpm", ["run", "start:dev"], {
            cwd: PROJECT_ROOT,
            stdio: "inherit",
            shell: true,
        });

        // Wait for child process to exit (keeps Node process alive)
        childProcess.on("exit", (code) => {
            log(`Nest.js dev server exited with code ${code}`, "\x1b[31m");
            gracefulShutdown();
        });

        return;
    }

    else if (arg1 === "stop") {
        gracefulShutdown();
        return;
    }

    // ------- HELP -------
    console.log(`
Usage:
  node dev-tools/dev.js start
  node dev-tools/dev.js start pull
  node dev-tools/dev.js stop
`);
}

main();
