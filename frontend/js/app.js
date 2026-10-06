// app.js - Common UI logic

// Currently empty but can be used to handle global theme toggles,
// websockets for real-time notifications, or common formatting functions.

function formatBytes(bytes, decimals = 2) {
    if (!Number.isFinite(Number(bytes)) || Number(bytes) <= 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
