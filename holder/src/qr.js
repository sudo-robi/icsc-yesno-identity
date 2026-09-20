// QR code generation and scanning facade
export function drawQR(canvas, text) {
  if (!window.QRScanner || !QRScanner.drawQR) return false;
  return QRScanner.drawQR(canvas, text);
}

export function createScanner(options) {
  if (!window.QRScanner || !window.ScanUtil) return null;
  return QRScanner.createScanner(options);
}

export function parseChallenge(text) {
  if (!window.ScanUtil) return null;
  return ScanUtil.parseChallenge(text);
}

export function validatePresentation(text) {
  if (!window.ScanUtil) return { ok: false, error: 'no-validator' };
  return ScanUtil.validatePresentation(text);
}