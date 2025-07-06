import logging
import sys
import os
import requests
import json
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify
import time

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


def parse_wechat_xml(xml_content):
    """自定义XML解析器，绕过库的用户信息解析问题"""
    try:
        root = ET.fromstring(xml_content)
        
        # 提取基本信息
        msg_info = {
            'to_user': root.find('ToUserName').text if root.find('ToUserName') is not None else '',
            'from_user': root.find('FromUserName').text if root.find('FromUserName') is not None else '',
            'create_time': root.find('CreateTime').text if root.find('CreateTime') is not None else '',
            'msg_type': root.find('MsgType').text if root.find('MsgType') is not None else '',
            'content': root.find('Content').text if root.find('Content') is not None else '',
            'msg_id': root.find('MsgId').text if root.find('MsgId') is not None else '',
            'agent_id': root.find('AgentID').text if root.find('AgentID') is not None else ''
        }
        
        logging.info(f"解析的消息信息: {msg_info}")
        return msg_info
    except Exception as e:
        logging.error(f"XML解析错误: {e}")
        return None


def create_custom_handler():
    """创建自定义的消息处理器"""
    app = Flask(__name__)
    
    # 创建WecomBotServer实例但不使用其消息处理
    server = WecomBotServer(
        token=os.getenv('WECOM_TOKEN', ''),
        aes_key=os.getenv('WECOM_AES_KEY', ''),
        corp_id=os.getenv('WECOM_CORP_ID', ''),
        logger_name=os.getenv('WECOM_BOT_NAME', '卷卷')
    )
    
    @app.route('/wecom_bot', methods=['POST'])
    def handle_message():
        try:
            # 获取查询参数
            msg_signature = request.args.get('msg_signature')
            timestamp = request.args.get('timestamp')
            nonce = request.args.get('nonce')
            
            # 获取加密的消息体
            echostr = request.args.get('echostr')
            if echostr:
                # 验证请求
                verified_str = server.verify_url(msg_signature, timestamp, nonce, echostr)
                return verified_str
            
            # 获取POST数据
            encrypt_msg = request.get_data()
            
            # 解密消息
            decrypted_msg = server.decrypt_msg(encrypt_msg, msg_signature, timestamp, nonce)
            logging.info(f"解密的消息: {decrypted_msg}")
            
            # 使用自定义解析器
            msg_info = parse_wechat_xml(decrypted_msg)
            if not msg_info:
                return "OK", 200
            
            # 处理消息
            if msg_info['msg_type'] == 'text':
                content = msg_info['content'].strip()
                
                # 移除@机器人的部分
                if content.startswith('@卷卷'):
                    content = content.replace('@卷卷', '').strip()
                
                logging.info(f"处理消息内容: {content}")
                
                # 获取 Coze 配置
                coze_token = os.getenv('COZE_API_TOKEN', '')
                bot_id = os.getenv('COZE_BOT_ID', '7522416985297469449')
                
                response_content = ""
                
                if content == 'help':
                    response_content = help_md()
                elif coze_token and content:
                    try:
                        response_content = call_coze_api(content, coze_token, bot_id)
                    except Exception as e:
                        logging.error(f"Coze integration failed: {e}")
                        response_content = f"收到消息: {content}"
                else:
                    response_content = f"收到消息: {content}"
                
                # 创建响应消息
                if response_content:
                    # 使用 server 的加密和发送功能
                    try:
                        # 构建响应XML
                        response_xml = f"""<xml>
<ToUserName><![CDATA[{msg_info['from_user']}]]></ToUserName>
<FromUserName><![CDATA[{msg_info['to_user']}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{response_content}]]></Content>
</xml>"""
                        
                        # 加密响应
                        encrypted_response = server.encrypt_msg(response_xml, timestamp, nonce)
                        return encrypted_response
                    except Exception as e:
                        logging.error(f"响应消息加密失败: {e}")
                        return "OK", 200
            
            return "OK", 200
            
        except Exception as e:
            logging.error(f"消息处理错误: {e}")
            return "OK", 200
    
    return app


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
        # 使用自定义处理器
        app = create_custom_handler()
        
        # 添加健康检查路由
        @app.route('/', methods=['GET'])
        def health_check():
            return "WeChat Work Bot is running! 🤖"
        
        # 添加验证路由
        @app.route('/wecom_bot', methods=['GET'])
        def verify_url():
            # 这个用于企业微信的URL验证
            echostr = request.args.get('echostr')
            msg_signature = request.args.get('msg_signature')
            timestamp = request.args.get('timestamp')
            nonce = request.args.get('nonce')
            
            if echostr:
                # 使用WecomBotServer来验证URL
                server = WecomBotServer(
                    token=token,
                    aes_key=aes_key,
                    corp_id=corp_id,
                    logger_name=bot_name
                )
                try:
                    verified_str = server.verify_url(msg_signature, timestamp, nonce, echostr)
                    return verified_str
                except Exception as e:
                    logging.error(f"URL验证失败: {e}")
                    return "Verification failed", 400
            
            return "WeChat Work Bot Endpoint", 200
        
        logging.info(f"Server starting on {host}:{port}/wecom_bot")
        app.run(host=host, port=port, debug=True)
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 