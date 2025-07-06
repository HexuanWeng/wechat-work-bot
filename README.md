# WeChat Work Bot Deployment

This is a WeChat Work bot server that can be deployed to Railway.

## Environment Variables

You need to set the following environment variables in Railway:

- `WECOM_TOKEN` - Your WeChat Work bot token
- `WECOM_AES_KEY` - Your WeChat Work bot AES key  
- `WECOM_CORP_ID` - Your WeChat Work company ID
- `WECOM_BOT_NAME` - Your bot name (default: 通知机器人)
- `WECOM_BOT_KEY` - Your bot webhook key (optional)
- `PORT` - Port number (Railway sets this automatically)

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

## Webhook URL

After deployment, your webhook URL will be:
`https://your-railway-app.railway.app/wecom_bot`

Configure this URL in your WeChat Work bot settings. 