"use client";

import { useEffect, useRef, useState } from "react";
import { Html5Qrcode } from "html5-qrcode";

interface QrScannerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScan: (result: string) => void;
}

export const QrScannerModal = ({ isOpen, onClose, onScan }: QrScannerModalProps) => {
  const [error, setError] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const isRunningRef = useRef(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    let mounted = true;
    const scannerId = "qr-scanner-container";

    const startScanner = async () => {
      setIsStarting(true);
      setError(null);

      try {
        // Create scanner instance
        const scanner = new Html5Qrcode(scannerId);
        scannerRef.current = scanner;

        // Get available cameras
        const cameras = await Html5Qrcode.getCameras();

        if (cameras.length === 0) {
          throw new Error("No cameras found on this device");
        }

        // Prefer back camera on mobile devices
        const backCamera = cameras.find(
          camera => camera.label.toLowerCase().includes("back") || camera.label.toLowerCase().includes("rear"),
        );
        const cameraId = backCamera?.id || cameras[0].id;

        // Start scanning
        await scanner.start(
          cameraId,
          {
            fps: 10,
            qrbox: { width: 250, height: 250 },
          },
          decodedText => {
            // Check if it's a WalletConnect URI
            if (decodedText.startsWith("wc:")) {
              console.log("Scanned WC URI:", decodedText);
              onScan(decodedText);
              handleClose();
            }
          },
          () => {
            // Ignore QR code not found errors (happens every frame without a QR)
          },
        );

        // Mark scanner as running
        isRunningRef.current = true;

        if (mounted) {
          setIsStarting(false);
        }
      } catch (err) {
        console.error("Failed to start scanner:", err);
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to start camera");
          setIsStarting(false);
        }
      }
    };

    startScanner();

    return () => {
      mounted = false;
      // Cleanup scanner on unmount - only if it's actually running
      if (scannerRef.current && isRunningRef.current) {
        isRunningRef.current = false;
        scannerRef.current
          .stop()
          .then(() => {
            scannerRef.current?.clear();
            scannerRef.current = null;
          })
          .catch(() => {
            // Ignore - scanner may already be stopped
          });
      }
    };
  }, [isOpen, onScan]);

  const handleClose = async () => {
    // Only stop if scanner is actually running
    if (scannerRef.current && isRunningRef.current) {
      isRunningRef.current = false;
      try {
        await scannerRef.current.stop();
        scannerRef.current.clear();
      } catch {
        // Ignore - scanner may already be stopped
      }
      scannerRef.current = null;
    }
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70" onClick={handleClose} />

      {/* Modal */}
      <div className="relative bg-base-100 rounded-2xl p-6 max-w-md w-full mx-4 shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-semibold">Scan QR Code</h3>
          <button className="btn btn-ghost btn-sm btn-circle" onClick={handleClose}>
            ✕
          </button>
        </div>

        {/* Scanner Container */}
        <div ref={containerRef} className="relative">
          {isStarting && (
            <div className="flex flex-col items-center justify-center py-12">
              <span className="loading loading-spinner loading-lg mb-4"></span>
              <p className="text-sm opacity-60">Starting camera...</p>
            </div>
          )}

          {error && (
            <div className="alert alert-error mb-4">
              <span>{error}</span>
            </div>
          )}

          {/* QR Scanner will render here */}
          <div
            id="qr-scanner-container"
            className="w-full rounded-lg overflow-hidden"
            style={{ minHeight: isStarting ? 0 : "300px" }}
          />
        </div>

        {/* Instructions */}
        <p className="text-sm text-center opacity-60 mt-4">Point your camera at a WalletConnect QR code</p>

        {/* Cancel Button */}
        <button className="btn btn-ghost w-full mt-4" onClick={handleClose}>
          Cancel
        </button>
      </div>
    </div>
  );
};
