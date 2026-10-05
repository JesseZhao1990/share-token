import type { Grant, Member, RequestRecord, Source } from '../../../packages/protocol/index.js';
import type { ClientDevice, ClientRequest, ClientSource } from '../../../packages/protocol/client.js';
import type { DonorSnapshot } from '../../../packages/client-core/donor.js';
import type { SubscriptionAccountStatus } from '../../../packages/upstream/subscription.js';
export interface LocalSession { id?: string; sessionId: string; model: string; sourceId: string; state: string; cwd?: string; pid?: number | null; message?: string | null; error?: string; errorCode?: string | null; exitCode?: number | null; exitSignal?: number | null; terminalStarted?: boolean }
export interface Pairing { userCode: string; verificationUriComplete: string; expiresAt: number; interval: number }
export interface HubTrustDisplay { hubUrl: string; label?: string; fingerprint256: string; validTo: string }
export interface State { connected: boolean; matchingRoom?: boolean; hubUrl?: string; member?: Member; device?: ClientDevice; members?: Member[]; sources?: ClientSource[]; grants?: Grant[]; requests?: ClientRequest[]; devices?: ClientDevice[]; sessions: LocalSession[]; sharing: DonorSnapshot | null; pairing: Pairing | null; deviceName: string; platform: string; version: string; credentialStorage: 'local-encrypted'; subscription: SubscriptionAccountStatus | null; subscriptionReady: boolean; experimentalSubscriptionEnabled: boolean; hubTrust: HubTrustDisplay | null; lastError?: string }
export interface Selection { id: string; path: string; version?: string; supported?: boolean }
export interface DesktopAPI {
  state(): Promise<State>; pair(args: { hubUrl: string; deviceName: string }): Promise<Pairing>;
  joinSpace(args: { hubUrl: string; deviceName: string; sharedCode: string }): Promise<void>;
  importHub(): Promise<HubTrustDisplay | null>; openHub(): Promise<void>;
  pollPairing(): Promise<{ status: string }>; cancelPairing(): Promise<void>; openPairing(): Promise<void>; logout(): Promise<{ revoked: boolean }>;
  selectDirectory(): Promise<Selection | null>; detectCodex(): Promise<Selection[]>; selectCodex(): Promise<Selection | null>;
  subscriptionSelect(executableId: string): Promise<SubscriptionAccountStatus>; subscriptionStatus(): Promise<SubscriptionAccountStatus>; subscriptionLogin(): Promise<{ loginId: string }>; subscriptionCancel(): Promise<void>; subscriptionLogout(): Promise<SubscriptionAccountStatus>;
  startSession(args: { sourceId: string; model: string; directoryId: string; executableId: string }): Promise<LocalSession>;
  stopSession(sessionId: string): Promise<void>; openTerminal(sessionId: string): Promise<void>;
  terminalAttach(): Promise<{ sessionId: string; backlog: string; sequence: number; session?: LocalSession }>; terminalWrite(data: string): Promise<void>; terminalResize(cols: number, rows: number): Promise<void>;
  saveSharing(args: unknown): Promise<unknown>; startSharing(): Promise<unknown>; pauseSharing(): Promise<unknown>; stopSharing(): Promise<unknown>; resolveSharing(): Promise<unknown>;
  revokeDevice(deviceId: string): Promise<unknown>; resolveDelivery(args: unknown): Promise<unknown>;
  exportDiagnostics(): Promise<{ path: string } | null>; quit(): Promise<void>;
  onEvent(callback: (event: { type: string; sessionId?: string; session?: LocalSession; data?: string; exitCode?: number; message?: string; sequence?: number }) => void): () => void;
}
declare global { interface Window { shareToken?: DesktopAPI } }
export const api = window.shareToken!;
