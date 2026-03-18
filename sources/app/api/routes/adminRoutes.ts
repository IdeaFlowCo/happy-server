import { randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import * as privacyKit from "privacy-kit";
import { Fastify } from "../types";
import { db } from "@/storage/db";
import { auth } from "@/app/auth/auth";
import { log } from "@/utils/log";

function secretsMatch(provided: string, expected: string) {
    const providedBytes = Buffer.from(provided);
    const expectedBytes = Buffer.from(expected);

    if (providedBytes.length !== expectedBytes.length) {
        return false;
    }

    return timingSafeEqual(providedBytes, expectedBytes);
}

export function adminRoutes(app: Fastify) {
    app.post("/v1/admin/provision", {
        schema: {
            headers: z.object({
                "x-admin-secret": z.string().optional(),
            }),
            response: {
                200: z.object({
                    userId: z.string(),
                    agentKey: z.object({
                        token: z.string(),
                        secret: z.string(),
                    }),
                }),
                401: z.object({
                    error: z.literal("Unauthorized"),
                }),
                500: z.object({
                    error: z.literal("Admin provisioning is not configured"),
                }),
            },
        },
    }, async (request, reply) => {
        const adminProvisionSecret = process.env.ADMIN_PROVISION_SECRET;
        if (!adminProvisionSecret) {
            log({ module: "admin-provision", level: "error" }, "ADMIN_PROVISION_SECRET is not configured");
            return reply.code(500).send({ error: "Admin provisioning is not configured" });
        }

        const providedSecret = request.headers["x-admin-secret"];
        if (typeof providedSecret !== "string" || !secretsMatch(providedSecret, adminProvisionSecret)) {
            log({ module: "admin-provision", level: "warn" }, "Rejected admin provisioning request with invalid secret");
            return reply.code(401).send({ error: "Unauthorized" });
        }

        const tweetnacl = (await import("tweetnacl")).default;
        const seed = randomBytes(tweetnacl.sign.seedLength);
        const signingKeyPair = tweetnacl.sign.keyPair.fromSeed(seed);
        const publicKeyHex = privacyKit.encodeHex(signingKeyPair.publicKey);

        const account = await db.account.create({
            data: {
                publicKey: publicKeyHex,
            },
        });

        const token = await auth.createToken(account.id);

        log({ module: "admin-provision", userId: account.id }, "Provisioned admin account");

        return reply.send({
            userId: account.id,
            agentKey: {
                token,
                secret: seed.toString("base64"),
            },
        });
    });
}
