import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.managemystaffing.app',
  appName: 'ManageMyStaffing',
  webDir: 'public',
  server: {
    // In production: load from the live URL instead of local assets
    url: 'https://www.managemystaffing.com/app',
    cleartext: false,
  },
  ios: {
    scheme: 'ManageMyStaffing',
    contentInset: 'automatic',
    backgroundColor: '#1B5E3B',
    preferredContentMode: 'mobile',
    allowsLinkPreview: false,
  },
  android: {
    // Android uses TWA (twa-manifest.json) — Capacitor config is iOS-only
    backgroundColor: '#1B5E3B',
  },
  plugins: {
    PushNotifications: {
      presentationOptions: ['badge', 'sound', 'alert'],
    },
    SplashScreen: {
      launchAutoHide: true,
      backgroundColor: '#1B5E3B',
      androidSplashResourceName: 'splash',
      showSpinner: false,
      splashFullScreen: false,
      splashImmersive: false,
      launchFadeOutDuration: 300,
    },
    StatusBar: {
      style: 'LIGHT',
      backgroundColor: '#1B5E3B',
    },
  },
};

export default config;
