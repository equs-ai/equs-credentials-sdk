import {createInterface} from "node:readline";

export async function readFromCLI(message: string): Promise<string> {
    return new Promise((resolve) => {
        const rl = createInterface({
            input: process.stdin,
            output: process.stdout,
        });

        rl.question(`${message} : `, (name) => {
            resolve(name);
            rl.close();
        });
    });
}
