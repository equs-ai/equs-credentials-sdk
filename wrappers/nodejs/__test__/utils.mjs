export function isEmpty(str) {
    return (!str || str.length === 0);
}

export function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}
