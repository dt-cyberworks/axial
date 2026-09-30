/**
 * REQ-CONSOLE-015: the QR-code library is only needed while a user enrolls
 * MFA, so it is loaded on demand instead of with every console page.
 */
export async function qrCodeDataUrl(text: string): Promise<string> {
  const { default: QRCode } = await import("qrcode");
  return QRCode.toDataURL(text, { width: 200 });
}

export const QR_LOADING = "Loading QR code…";
export const QR_FAILED = "The QR code could not be loaded. Enter the key below by hand, or reload the page.";
