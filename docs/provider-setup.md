# Provider setup

Text message, WhatsApp and voice codes are delivered and checked by a managed verification service. Each site selects one provider under **Settings → Potomac MFA → Connection**. One provider account can serve every site.

Email and authenticator-app codes do not use a provider.

## Twilio Verify

### Verify Service

1. In the Twilio Console, navigate to **Verify → Services** and click **Create new**.
2. Enter a **Friendly name**. It appears in the message text, e.g., "Your Potomac Technologies verification code is: 123456". One service can serve every site. For per-client wording, create a service per client.
3. Enable the **SMS** and **Voice** channels. Enable **WhatsApp** only after completing the WhatsApp steps below.
4. Leave **Code length** at 6.
5. Click **Create**, then copy the **Service SID** (begins with `VA`).

### API key

API keys are recommended over the account auth token, because a key can be revoked without affecting anything else on the account.

1. Navigate to **Account → API keys & tokens** (Admin → Account management → API keys & tokens in the newer Console).
2. Click **Create API key**. Enter a name, e.g., "Potomac MFA", and select the **Standard** key type.
3. Copy the **SID** (begins with `SK`) and the **Secret**. The secret is shown once. Store it in a password manager.

Enter the Account SID (`AC…`), API key SID, API key secret and Verify Service SID on the **Connection** tab, or add them to the base configuration file.

### Fraud and cost controls

SMS pumping attacks send codes to premium-rate numbers to generate revenue for the attacker. Potomac MFA only sends a code after the correct password has been entered, which limits exposure. The following Twilio settings add further protection:

- **Fraud Guard:** navigate to **Verify → Fraud Guard** and confirm protection is enabled (the default is *Standard*).
- **Geo permissions:** navigate to **Verify → Settings → Geo permissions** and allow only the countries where users are located, e.g., the United States and Canada.
- **Usage triggers:** under **Monitor → Usage triggers**, add an alert for Verify spend above a monthly threshold.

### WhatsApp

Meta requires WhatsApp verification messages to be sent from the business's own WhatsApp sender. Setup takes about an hour, plus Meta business verification, which typically takes 1–2 weeks.

1. Navigate to **Messaging → Senders → WhatsApp senders** and complete self sign-up to create a WhatsApp Business Account (WABA) and register a phone number. A number that is not used for marketing messages is recommended.
2. Create a Messaging Service (**Messaging → Services**) and add the WhatsApp sender to it.
3. Open the Verify Service, select the **WhatsApp** tab, and select the Messaging Service (`MG…`).
4. In Potomac MFA, enable **WhatsApp** under **Methods**, then send a test code from the **Connection** tab.

Until these steps are complete, leave WhatsApp disabled. Twilio returns error 63008 when no Messaging Service is configured.

### Cost reference (US, October 2026)

Twilio charges $0.05 per successful verification plus the channel fee: about $0.0083 per SMS, plus carrier fees. Email and authenticator-app sign-ins cost nothing. Trusted browsers reduce how often codes are sent.

## Plivo Verify

Plivo charges no per-verification fee, only channel charges (about $0.0077 per US SMS, plus carrier fees). Plivo's documentation states that Verify is offered to direct brands and requires a minimum monthly commitment. Confirm availability with Plivo sales before switching.

1. In the Plivo Console, navigate to **Verify → Applications** and create an application. Set the code length (6), expiry (10 minutes), channels (SMS, Voice) and the Fraud Shield level.
2. Copy the application **UUID**.
3. Copy the **Auth ID** and **Auth Token** from the Console overview page.
4. In Potomac MFA, select **Plivo Verify** under **Connection**, enter the values, save, and click **Test connection**.

Plivo's API reference documents the SMS and voice channels. WhatsApp may require enablement on the Plivo account; send a test code before enabling it for users.

## Switching providers

Phone numbers are stored on the site, not at the provider, so switching providers requires no re-enrollment. Codes already sent through the previous provider remain valid until they expire.
