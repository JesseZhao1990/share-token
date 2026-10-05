import type { Grant, Member, RequestRecord, Source } from './index.js';

/** Additive desktop-control contract. These credentials authenticate to this Hub, not OpenAI. */
export type DeviceScope = 'consumer' | 'donor';
export interface ClientDevice { id: string; memberId: string; name: string; platform: string; clientVersion: string; scopes: DeviceScope[]; status: 'active' | 'revoked'; createdAt: number; lastSeen: number }
export interface DevicePairingResponse { pairingId: string; deviceCode: string; userCode: string; verificationUri: string; verificationUriComplete: string; expiresAt: number; interval: number }
export interface DevicePairingView { pairingId: string; deviceName: string; platform: string; clientVersion: string; requestedScopes: DeviceScope[]; approvedScopes: DeviceScope[]; status: 'pending' | 'approved' | 'denied' | 'cancelled' | 'redeemed' | 'expired'; expiresAt: number }
export interface ClientAuthResponse { accessToken: string; refreshToken: string; tokenType: 'Bearer'; expiresIn: number; refreshExpiresAt: number; device: ClientDevice; member: Member }
export interface ClientSession { id: string; memberId: string; grantId: string; sourceId: string; modelScope: string[]; state: 'open' | 'closed'; frozen: boolean; createdAt: number }
export interface RunLease { id: string; sessionId: string; deviceId: string; epoch: number; state: 'active' | 'closed' | 'revoked' | 'expired'; expiresAt: number; createdAt: number }
export interface RelayLease { id: string; sourceId: string; deviceId: string; state: 'active' | 'closed' | 'revoked' | 'expired'; expiresAt: number; createdAt: number }
export interface RunLeaseResponse { lease: RunLease; token: string; expiresIn: number }
export interface RelayLeaseResponse { lease: RelayLease; token: string; expiresIn: number }
export interface ClientSource extends Source { clientMode?: 'mock-v1-compatibility' | 'subscription-v1-compatibility' | 'unavailable'; policyRevision?: number; appliedPolicyRevision?: number }
export interface ClientRequest extends RequestRecord { sessionId: string; leaseId: string; deviceId: string; operationId: string; consumerDelivery: 'pending' | 'transport_finished' | 'lost' | 'unknown' }
export interface ClientSourceResponse { source: ClientSource; revision: number; appliedRevision: number }
export interface ClientGrantResponse { grant: Grant }
export interface ClientMeta { hubId: string; spaceName: string; apiVersion: 2; relayProtocolVersion: 1; desktopDataPlane: 'responses-v1'; subscriptionAvailable: boolean; pairing: { method: 'S256'; expiresIn: number; interval: number; sharedCodeAvailable?: boolean; matchingCodeAvailable?: boolean }; features: string[] }
