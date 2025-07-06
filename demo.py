import logging
import sys
import os
import requests
import json
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, Response
import time

from wecom_bot_svr import WecomBotServer, RspMarkdownMsg, ReqMsg
from wecom_bot_svr.req_msg import TextReqMsg


def help_md():
    return """🤖 **卷卷 AI 助手使用指南**

🎯 **主要功能：**
• 智能对话：直接发送消息与 AI 对话
• 业务咨询：处理增删改查相关业务需求
• 智能问答：回答各类问题和提供建议

💬 **使用方法：**
• @卷卷 你的问题或需求
• 例如：@卷卷 请帮我分析一下数据
• 例如：@卷卷 如何优化数据库查询

📞 **获取帮助：**
• 发送 help、帮助、? 获取此帮助信息

✨ **由 Coze AI 智能体驱动**
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
        
        logging.info(f"🤖 调用 Coze API - 消息: {message}")
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            logging.info(f"✅ Coze API 响应成功: {result}")
            
            # 提取回复内容
            if 'messages' in result and len(result['messages']) > 0:
                for msg in result['messages']:
                    if msg.get('type') == 'answer':
                        ai_response = msg.get('content', '抱歉，我没有理解你的问题。').strip()
                        # 清理回复内容，移除多余的空格和换行
                        ai_response = ' '.join(ai_response.split())
                        # 限制回复长度，避免超过企业微信限制
                        if len(ai_response) > 2000:
                            ai_response = ai_response[:1900] + "...\n\n(回复内容过长，已截断)"
                        
                        logging.info(f"🎯 AI 回复内容: {ai_response}")
                        return ai_response
            
            logging.warning("⚠️ Coze API 响应中没有找到有效的回复内容")
            return "抱歉，我暂时无法回答你的问题。"
        else:
            logging.error(f"❌ Coze API 调用失败: {response.status_code}, {response.text}")
            return "抱歉，AI 服务暂时不可用。"
    
    except Exception as e:
        logging.error(f"💥 Coze API 调用异常: {str(e)}")
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
    
    # 消息去重缓存 - 防止重复处理
    processed_messages = set()
    
    # 创建WecomBotServer实例用于加密解密
    def get_server():
        return WecomBotServer(
            name=os.getenv('WECOM_BOT_NAME', '卷卷'),
            host='0.0.0.0',
            port=int(os.getenv('PORT', 8080)),
            path='/wecom_bot',
            token=os.getenv('WECOM_TOKEN', ''),
            aes_key=os.getenv('WECOM_AES_KEY', ''),
            corp_id=os.getenv('WECOM_CORP_ID', ''),
            bot_key=os.getenv('WECOM_BOT_KEY', '')
        )
    
    def get_crypto_obj():
        return get_server().get_crypto_obj()
    
    @app.route('/', methods=['GET'])
    def health_check():
        return "WeChat Work Bot is running! 🤖"
    
    @app.route('/test_response', methods=['GET'])
    def test_response():
        """测试响应格式"""
        # 创建完整的企业微信回复格式测试
        current_time = int(time.time())
        test_xml = f"""<xml>
<ToUserName><![CDATA[test_user]]></ToUserName>
<FromUserName><![CDATA[{os.getenv('WECOM_CORP_ID', 'test_corp')}]]></FromUserName>
<CreateTime>{current_time}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[这是一个测试消息]]></Content>
</xml>"""
        
        return Response(
            f"Test XML Response:\n{test_xml}",
            status=200,
            headers={'Content-Type': 'text/plain; charset=utf-8'}
        )
    
    @app.route('/wecom_bot', methods=['GET'])
    def verify_url():
        # 企业微信URL验证 - 按照官方文档要求实现
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        
        logging.info(f"🔍 URL验证请求 - echostr存在: {echostr is not None}")
        logging.info(f"📋 参数: msg_signature={msg_signature}, timestamp={timestamp}, nonce={nonce}")
        
        if echostr:
            try:
                # 使用加密解密器验证URL - 按照企业微信官方流程
                crypto_obj = get_crypto_obj()
                ret, decrypted_echo_str = crypto_obj.VerifyURL(msg_signature, timestamp, nonce, echostr)
                
                logging.info(f"🔒 验证结果: ret={ret}")
                
                if ret != 0:
                    logging.error(f"❌ URL验证失败，错误代码: {ret}")
                    return None  # 按照企业微信文档，验证失败返回None
                
                logging.info(f"✅ URL验证成功，返回解密字符串")
                # 按照企业微信文档要求：在1秒内原样返回明文消息内容(不能加引号，不能带bom头，不能带换行符)
                return decrypted_echo_str
                
            except Exception as e:
                logging.error(f"💥 URL验证异常: {e}")
                return None
        
        # 无echostr参数时返回基本信息
        return "WeChat Work Bot Endpoint", 200
    
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
                crypto_obj = get_crypto_obj()
                ret, verified_str = crypto_obj.VerifyURL(msg_signature, timestamp, nonce, echostr)
                if ret != 0:
                    return "Verification failed", 400
                return verified_str
            
            # 获取POST数据
            encrypt_msg = request.get_data()
            
            # 解密消息
            crypto_obj = get_crypto_obj()
            ret, decrypted_msg = crypto_obj.DecryptMsg(encrypt_msg, msg_signature, timestamp, nonce)
            if ret != 0:
                logging.error(f"解密消息失败: {ret}")
                return "OK", 200
            
            logging.info(f"解密的消息: {decrypted_msg.decode()}")
            
            # 使用自定义解析器
            msg_info = parse_wechat_xml(decrypted_msg.decode())
            if not msg_info:
                return "OK", 200
            
            # 消息去重检查
            msg_id = msg_info.get('msg_id', '')
            if msg_id in processed_messages:
                logging.warning(f"🔄 检测到重复消息，跳过处理: {msg_id}")
                logging.info(f"📊 当前已处理消息数量: {len(processed_messages)}")
                return "OK", 200
            
            # 添加到已处理列表
            processed_messages.add(msg_id)
            logging.info(f"📝 新消息处理开始，消息ID: {msg_id}")
            
            # 限制缓存大小，避免内存泄漏
            if len(processed_messages) > 1000:
                processed_messages.clear()
                logging.info("🧹 消息缓存已清理")
            
            # 处理消息
            if msg_info['msg_type'] == 'text':
                content = msg_info['content'].strip()
                
                # 移除@机器人的部分
                bot_name = os.getenv('WECOM_BOT_NAME', '卷卷')
                if content.startswith(f'@{bot_name}'):
                    content = content.replace(f'@{bot_name}', '').strip()
                
                logging.info(f"📝 处理消息内容: {content}")
                
                # 获取 Coze 配置
                coze_token = os.getenv('COZE_API_TOKEN', '')
                bot_id = os.getenv('COZE_BOT_ID', '7522416985297469449')
                
                response_content = ""
                
                # 处理不同类型的消息
                if content.lower() in ['help', '帮助', '?', '？']:
                    response_content = help_md()
                    logging.info("📖 返回帮助信息")
                elif coze_token and content:
                    try:
                        logging.info(f"🚀 开始调用 Coze AI 处理消息: {content}")
                        response_content = call_coze_api(content, coze_token, bot_id)
                        logging.info(f"✨ AI 处理完成，准备发送回复")
                    except Exception as e:
                        logging.error(f"❌ Coze 集成失败: {e}")
                        response_content = f"AI处理出错，收到您的消息: {content}"
                else:
                    response_content = f"收到您的消息: {content}"
                    logging.info(f"📤 返回简单回复")
                
                # 创建并发送响应消息
                if response_content:
                    try:
                        logging.info(f"🔄 开始创建响应消息...")
                        
                        # 创建完整的企业微信回复格式
                        current_time = int(time.time())
                        response_xml = f"""<xml>
<ToUserName><![CDATA[{msg_info['from_user']}]]></ToUserName>
<FromUserName><![CDATA[{msg_info['to_user']}]]></FromUserName>
<CreateTime>{current_time}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{response_content}]]></Content>
</xml>"""
                        
                        # 转换为字节格式用于加密
                        response_xml_bytes = response_xml.encode('utf-8')
                        
                        logging.info(f"📋 生成的响应XML: {response_xml}")
                        
                        # 加密响应 - 传递字节类型
                        ret, encrypted_response = crypto_obj.EncryptMsg(
                            response_xml_bytes, 
                            nonce, 
                            timestamp
                        )
                        
                        if ret != 0:
                            logging.error(f"❌ 加密响应失败，错误代码: {ret}")
                            # 即使失败也要返回成功状态，避免企业微信重试
                            return "OK", 200
                        
                        logging.info(f"🔒 消息加密成功，准备发送回复")
                        
                        # 企业微信期望返回纯字符串格式的响应
                        if isinstance(encrypted_response, bytes):
                            final_response = encrypted_response.decode('utf-8')
                        else:
                            final_response = str(encrypted_response)
                        
                        logging.info(f"📤 返回响应到企业微信，长度: {len(final_response)}")
                        logging.info(f"🎯 AI回复已发送: {response_content}")
                        logging.info(f"🚀 响应已直接返回给企业微信")
                        logging.info(f"📨 响应预览（前100字符）: {final_response[:100]}...")
                        
                        # 返回加密的XML响应，不需要额外的HTTP响应包装
                        return final_response
                        
                    except Exception as e:
                        logging.error(f"💥 响应消息处理失败: {e}")
                        import traceback
                        logging.error(f"详细错误: {traceback.format_exc()}")
                        # 即使处理失败，也返回成功状态，避免企业微信重试
                        return "OK", 200
                else:
                    logging.warning("⚠️ 没有生成响应内容")
                    return "OK", 200
            
            return "OK", 200
            
        except Exception as e:
            logging.error(f"💥 全局消息处理错误: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
            # 确保返回200状态，避免企业微信重试
            return "OK", 200
        finally:
            # 确保无论如何都有响应
            logging.info(f"📊 消息处理完成，消息ID: {msg_info.get('msg_id', 'unknown') if 'msg_info' in locals() else 'unknown'}")
    
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
        
        logging.info(f"🚀 Server starting on {host}:{port}/wecom_bot")
        logging.info(f"🎯 Ready to receive messages and respond with AI!")
        
        # 生产环境关闭debug模式
        is_debug = os.getenv('DEBUG', 'False').lower() == 'true'
        app.run(host=host, port=port, debug=is_debug)
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 