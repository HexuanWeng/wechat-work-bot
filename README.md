# WeChat Work Bot Deployment

This is a WeChat Work bot server that can be deployed to Railway.

## Environment Variables

You need to set the following environment variables in Railway:

- `WECOM_TOKEN` - Your WeChat Work bot token
- `WECOM_AES_KEY` - Your WeChat Work bot AES key  
- `WECOM_CORP_ID` - Your WeChat Work company ID
- `WECOM_BOT_NAME` - Your bot name (default: 卷卷)
- `WECOM_BOT_KEY` - Your bot webhook key (optional)
- `PORT` - Port number (Railway sets this automatically - DON'T set this manually)
- `COZE_API_TOKEN` - Your Coze API token (optional, for AI integration)
- `COZE_BOT_ID` - Your Coze bot ID (optional, for AI integration)

## Deployment to Railway

1. Push this repository to GitHub
2. Connect Railway to your GitHub repository
3. Set the environment variables in Railway dashboard
4. Deploy!

## Bot Features

- Responds to "help" command with help information
- Can send files when requested
- Handles group chat events
- Supports @mentions in group chats
- **AI Integration**: Powered by Coze AI for intelligent conversations
- **Smart Replies**: All messages (except commands) are processed by AI

## Webhook URL

After deployment, your webhook URL will be:
`https://your-railway-app.railway.app/wecom_bot`

Configure this URL in your WeChat Work bot settings. 