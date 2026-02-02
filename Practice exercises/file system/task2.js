
const fs = require("fs").promises;

async function main() {
  const [,, command, ...args] = process.argv;

  try {
    switch (command) {
      case "read":
        const data = await fs.readFile(args[0], "utf8");
        console.log("File content:\n", data);
        break;

      case "write":
        await fs.writeFile(args[0], args[1], "utf8");
        console.log("File written successfully!");
        break;

      case "append":
        await fs.appendFile(args[0], args[1] + "\n", "utf8");
        console.log("Content appended!");
        break;

      case "copy":
        await fs.copyFile(args[0], args[1]);
        console.log("File copied!");
        break;

      case "delete":
        await fs.unlink(args[0]);
        console.log("File deleted!");
        break;

      case "list":
        const files = await fs.readdir(args[0] || ".");
        console.log("Files in directory:");
        files.forEach(f => console.log(" - " + f));
        break;

      default:
        console.log("Unknown command. Use: read | write | append | copy | delete | list");
    }
  } catch (err) {
    if (err.code === "ENOENT") {
      console.error("Error: File or directory not found.");
    } else if (err.code === "EACCES") {
      console.error("Error: Permission denied.");
    } else {
      console.error("Error:", err.message);
    }
  }
}

main();