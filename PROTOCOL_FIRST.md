# 鍗忚涓绘祦绋嬩笌楠岃瘉鐮佺獥鍙?
褰撳墠杩愯妯″瀷鏄€滃崗璁紭鍏堬紝楠岃瘉鐮佹墠寮规祻瑙堝櫒鈥濄€傛祻瑙堝櫒鍙弬涓庢粦鍧楋紝娉ㄥ唽銆佹敹淇°€?婵€娲诲拰 OAuth 鎹㈢エ閮藉湪鍗忚瀹㈡埛绔畬鎴愩€傝嚜鍔ㄦ眰瑙ｃ€乯sdom銆佸閮?solver銆丆DP 鎶曞睆
鍜岃繙绋嬮紶鏍囧洖鏀惧潎宸蹭粠杩愯璺緞鍒犻櫎銆?
## 1. 杩愯閾捐矾

```text
浠诲姟闃熷垪
  -> ZaiProtocolClient 寤虹珛 guest 浼氳瘽
  -> 鍙€夎处鍙峰瓨鍦ㄦ€ф鏌?  -> 浠呴獙璇佺爜闃舵鎵撳紑鏈満 Chromium锛坔eadless=false锛?  -> 鑷姩濉啓 name/email/password 骞惰Е鍙戞粦鍧?  -> 鎿嶄綔鑰呬翰鎵嬫嫋鍔?  -> 鎹曡幏 captcha_verify_param 涓庡悓浼氳瘽 Cookie
  -> 鍏抽棴娴忚鍣?  -> 鍗忚瀹㈡埛绔彁浜?signup锛堟垨瀵煎叆娴忚鍣ㄥ凡瀹屾垚鐨?signup锛?  -> 鑷姩鏀堕偖浠?  -> finish_signup
  -> ZCode OAuth CLI
  -> 淇濆瓨 Web JWT / CLI JWT / Device MID
```

## 2. 杩愯閰嶇疆

```json
{
  "registration_mode": "protocol",
  "headless": false,
  "protocol_fallback_browser": false,
  "captcha_timeout_sec": 600,
  "target_count": 1
}
```

娴忚鍣ㄧ獥鍙ｆ暟鍥哄畾涓?1銆傜洰鏍囪处鍙锋暟琛ㄧず鏈闃熷垪澶勭悊澶氬皯涓处鍙凤紝瀹屾垚涓€涓处鍙峰悗
鍐嶆墦寮€涓嬩竴涓獙璇佺爜绐楀彛銆?
## 3. 楠岃瘉鐮佸鐞嗚竟鐣?
绋嬪簭浼氾細

- 鑷姩濉啓楠岃瘉鐮佹祻瑙堝櫒閲岀殑娉ㄥ唽琛ㄥ崟銆?- 鑷姩鐐瑰嚮鍒涘缓璐﹀彿鍜岄獙璇佺爜鍏ュ彛銆?- 杞椤甸潰鏄惁鏄剧ず楠岃瘉鎴愬姛銆?- 鎹曡幏娴忚鍣ㄥ彂鍑虹殑 signup 璇锋眰鍜屽搷搴斻€?- 鍦ㄦ祻瑙堝櫒鍙敓鎴?token 鑰屾湭鎻愪氦鏃讹紝鎶?token 浜ょ粰鍗忚瀹㈡埛绔彁浜ゃ€?
绋嬪簭涓嶄細锛?
- 璇嗗埆婊戝潡缂哄彛銆?- 鐢熸垚鎷栧姩杞ㄨ抗銆?- 璋冪敤浠讳綍鑷姩姹傝В鍣ㄣ€?- 閫氳繃 CDP 鎺ㄦ祦銆?- 鍚戦〉闈㈠洖鏀鹃紶鏍囨垨瑙︽懜浜嬩欢銆?- 鎶婇獙璇佺爜浼氳瘽璺ㄦ満鍣ㄤ紶杈撱€?
## 4. 鏃ュ織

鏃ュ織鏂囦欢锛?
```text
logs/register-debug.log
```

Web 鏌ョ湅锛?
```text
http://127.0.0.1:8765/api/debug-log
http://127.0.0.1:8765/api/traffic-log
```

鎶撳寘鏂囦欢锛?
```text
logs/traffic-capture.jsonl
```

瀹冭褰曞崗璁鎴风鍜岄獙璇佺爜 Chromium 鐨勮姹?鍝嶅簲 URL銆佹柟娉曘€佺姸鎬併€佽€楁椂銆?鍏抽敭澶翠笌鍝嶅簲浣撴憳瑕侊紱鏁忔劅鍊间細鑴辨晱銆?
鎸?`task_id` 杩囨护鍗冲彲涓茶仈涓€娆′换鍔°€備富瑕佷簨浠讹細

| 浜嬩欢 | 鍚箟 |
|---|---|
| `protocol.start` | 鍗忚浠诲姟寮€濮?|
| `protocol.guest_ready` | 璁垮浼氳瘽宸插缓绔?|
| `captcha.window.start` | 浠呴獙璇佺爜娴忚鍣ㄥ惎鍔?|
| `captcha.auth_loaded` | 楠岃瘉鐮侀〉闈㈠凡鍔犺浇 |
| `captcha.console` | 楠岃瘉鐮侀〉闈㈡帶鍒跺彴杈撳嚭 |
| `captcha.request_failed` | 楠岃瘉鐮佽祫婧愬姞杞藉け璐?|
| `captcha.signup_request` | 娴忚鍣?signup 璇锋眰涓?token 鎽樿 |
| `captcha.signup_response` | 娴忚鍣?signup 鍝嶅簲 |
| `captcha.window.completed` | 宸插彇寰?token/Cookie锛屾祻瑙堝櫒灏嗗叧闂?|
| `protocol.signup_completed` | 鍗忚瀹㈡埛绔畬鎴?signup |
| `protocol.email_verified` | 閭婵€娲诲苟鍙栧緱 Web JWT |
| `protocol.completed` | CLI JWT 涓?Device MID 鎻愬彇瀹屾垚 |
| `protocol.failed` | 鍗忚闃舵寮傚父鍜屽爢鏍?|
| `export.cli_jwt` | tokens.txt 瀵煎嚭涓庤烦杩囩粺璁?|

瀵嗙爜銆丆ookie銆丣WT銆乣captcha_verify_param` 涓嶄細瀹屾暣鍐欏叆鏃ュ織銆?
## 5. 鍚姩

```powershell
cd pro-zai
powershell -ExecutionPolicy Bypass -File .\start-local.ps1
```

鎵嬪姩鏂瑰紡锛?
```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
python -m uvicorn app:app --host 127.0.0.1 --port 8765
```

鎵撳紑 <http://127.0.0.1:8765>銆?
## 6. 鎿嶄綔

1. 瀵煎叆浠诲姟鎴栦粠閭姹犵敓鎴愪换鍔°€?2. 璁剧疆鐩爣璐﹀彿鏁帮紝鐐瑰嚮寮€濮嬨€?3. 鍗忚瀹㈡埛绔厛寤虹珛浼氳瘽锛涘彧鏈夐獙璇佺爜闃舵浼氬脊鍑?Chromium銆?4. 浜叉墜鎷栧姩婊戝潡銆?5. 椤甸潰鏄剧ず楠岃瘉鎴愬姛鍚庯紝娴忚鍣ㄨ嚜鍔ㄥ叧闂紝鍗忚缁х画娉ㄥ唽鍜屾縺娲汇€?6. 澶辫触鏃跺彲鐩存帴閲嶆柊鎷栧姩锛屼笉闇€瑕侀噸鍚换鍔°€?7. 涓嶈鎵嬪姩鍏抽棴楠岃瘉鐮佺獥鍙ｏ紱鍏抽棴浼氱粓姝㈠綋鍓嶄换鍔°€?
## 7. 鎺掓煡

### 楠岃瘉鐮佸叆鍙ｆ湭鍑虹幇

鏌ョ湅锛?
```text
captcha.window.start
captcha.auth_loaded
captcha.console
captcha.request_failed
```

閫氬父鏄樋閲屼簯闈欐€佽祫婧愯浠ｇ悊闃绘柇銆傛鏌ヤ唬鐞嗘槸鍚﹀厑璁?`static-captcha*.aliyuncs.com`銆?
### 婊戝潡閫氳繃浣嗘敞鍐屽け璐?
鏌ョ湅锛?
```text
captcha.window.completed
captcha.signup_request
captcha.signup_response
protocol.signup_completed
protocol.failed
```

濡傛灉娴忚鍣ㄥ凡缁忓畬鎴?signup锛岀▼搴忎細瀵煎叆鍚屼細璇?Cookie锛岀敱鍗忚瀹㈡埛绔户缁偖浠?楠岃瘉鍜?OAuth锛屼笉浼氶噸澶嶆敞鍐屻€?
### 娴忚鍣ㄦ病鏈夊脊鍑?
纭 `headless=false`锛屽苟妫€鏌ワ細

```powershell
python -m playwright install chromium
```

### 瀵煎嚭涓轰粈涔堝皯浜庢垚鍔熻处鍙锋暟

`tokens.txt` 鍙鍑虹湡姝ｇ殑 CLI JWT銆傚彧鏈?Web JWT銆佹病鏈?`cli_jwt` 鐨勪换鍔′細琚烦杩囷紱
鏌ョ湅 `export.cli_jwt` 浜嬩欢涓殑 `exported` 涓?`skipped`銆?
### 鏃ュ織鑴辨晱鏄惁鐢熸晥

鏃ュ織涓殑鏁忔劅瀛楁浼氭樉绀轰负鍓嶇紑銆佸悗缂€銆侀暱搴﹀拰 SHA-256 鎽樿锛岃€屼笉鏄槑鏂囥€?