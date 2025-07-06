import logging
import sys
import os
import requests
import json

from wecom_bot_svr import WecomBotServer, RspTextMsg, RspMarkdownMsg, ReqMsg
from wecom_bot_svr.req_msg import TextReqMsg


def help_md():
    return """### Help 列表
- [给项目点赞](https://github.com/easy-wx/wecom-bot-svr)
- 发送任何消息与 AI 智能体对话
- 其他功能请自行开发
"""


def call_coze_api(message, coze_token, bot_id):
    """
    调用 Coze API 获取智能回复
    """
    try:
        url = "https://api.coze.cn/open_api/v2/chat"
        headers = {
            'Authorization': f'Bearer {coze_token}',
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Host': 'api.coze.cn',
            'Connection': 'keep-alive'
        }
        
        data = {
            "conversation_id": "123",
            "bot_id": bot_id,
            "user": "user",
            "query": message,
            "stream": False
        }
        
        logging.info(f"调用 Coze API - 消息: {message}")
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            logging.info(f"Coze API 响应: {result}")
            
            # 提取回复内容
            if 'messages' in result and len(result['messages']) > 0:
                for msg in result['messages']:
                    if msg.get('type') == 'answer':
                        return msg.get('content', '抱歉，我没有理解你的问题。')
            
            return "抱歉，我暂时无法回答你的问题。"
        else:
            logging.error(f"Coze API 调用失败: {response.status_code}, {response.text}")
            return "抱歉，AI 服务暂时不可用。"
    
    except Exception as e:
        logging.error(f"Coze API 调用异常: {str(e)}")
        return "抱歉，AI 服务出现异常。"


def msg_handler(req_msg: ReqMsg, server: WecomBotServer):
    # 添加调试日志
    logging.info(f"收到消息 - 类型: {req_msg.msg_type}, 内容: {getattr(req_msg, 'content', '无内容')}")
    
    # 获取 Coze 配置
    coze_token = os.getenv('COZE_API_TOKEN', '')
    bot_id = os.getenv('COZE_BOT_ID', '7522416985297469449')
    
    # 处理文本消息
    if req_msg.msg_type == 'text' and isinstance(req_msg, TextReqMsg):
        message_content = req_msg.content.strip()
        
        # 本地命令处理
        if message_content == 'help':
            ret = RspMarkdownMsg()
            ret.content = help_md()
            return ret
        elif message_content == 'give me a file' and server is not None:
            # 生成文件、发送文件可以新启线程异步处理
            with open('output.txt', 'w') as f:
                f.write("This is a test file. Welcome to star easy-wx/wecom-bot-svr!")
            server.send_file(req_msg.chat_id, 'output.txt')
            return RspTextMsg()  # 不发送消息，只回复文件
        
        # 如果配置了 Coze，发送给 AI 智能体处理
        elif coze_token and message_content:
            try:
                ai_response = call_coze_api(message_content, coze_token, bot_id)
                ret = RspTextMsg()
                ret.content = ai_response
                return ret
            except Exception as e:
                logging.error(f"Coze integration failed: {e}")
                # 降级到基本回复
                ret = RspTextMsg()
                ret.content = f"收到消息: {message_content}"
                return ret
    
    # 默认返回消息类型
    ret = RspTextMsg()
    ret.content = f'msg_type: {req_msg.msg_type}'
    return ret


def event_handler(req_msg):
    ret = RspMarkdownMsg()
    if req_msg.event_type == 'add_to_chat':  # 入群事件处理
        ret.content = f'msg_type: {req_msg.msg_type}\n群会话ID: {req_msg.chat_id}\n查询用法请回复: help'
    return ret


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    # Get credentials from environment variables
    token = os.getenv('WECOM_TOKEN', '')
    aes_key = os.getenv('WECOM_AES_KEY', '')
    corp_id = os.getenv('WECOM_CORP_ID', '')
    host = '0.0.0.0'
    # Railway automatically sets PORT, default to 8080 if not set
    port = int(os.getenv('PORT', 8080))
    bot_key = os.getenv('WECOM_BOT_KEY', '')

    # 这里要跟机器人名字一样，用于切分群组聊天中的@消息
    bot_name = os.getenv('WECOM_BOT_NAME', '卷卷')
    
    # Get Coze configuration
    coze_token = os.getenv('COZE_API_TOKEN', '')
    coze_bot_id = os.getenv('COZE_BOT_ID', '7522416985297469449')
    
    # Print configuration for debugging
    logging.info(f"=== Starting WeChat Work Bot: {bot_name} ===")
    logging.info(f"Port: {port}")
    logging.info(f"Token: {'*' * len(token) if token else 'NOT SET'}")
    logging.info(f"AES Key: {'*' * len(aes_key) if aes_key else 'NOT SET'}")
    logging.info(f"Corp ID: {'*' * len(corp_id) if corp_id else 'NOT SET'}")
    logging.info(f"Coze API Token: {'*' * len(coze_token) if coze_token else 'NOT SET'}")
    logging.info(f"Coze Bot ID: {coze_bot_id}")
    logging.info(f"=== Configuration Complete ===")
    
    # Validate required environment variables
    if not token or not aes_key or not corp_id:
        logging.error("Missing required environment variables:")
        logging.error(f"WECOM_TOKEN: {'✓' if token else '✗'}")
        logging.error(f"WECOM_AES_KEY: {'✓' if aes_key else '✗'}")
        logging.error(f"WECOM_CORP_ID: {'✓' if corp_id else '✗'}")
        sys.exit(1)
    
    try:
        server = WecomBotServer(bot_name, host, port, path='/wecom_bot', token=token, aes_key=aes_key, corp_id=corp_id,
                                bot_key=bot_key)

        server.set_message_handler(msg_handler)
        server.set_event_handler(event_handler)
        
        logging.info(f"Server starting on {host}:{port}/wecom_bot")
        server.run()
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 