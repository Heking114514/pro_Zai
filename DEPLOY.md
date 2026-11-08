# Docker 闁劎璁?
## 1. 閺堫剙婀撮弸鍕紦

```powershell
docker build -t pro-zai:latest .
```

闂€婊冨剼閸栧懎鎯?Playwright Chromium閵嗕赋ython 娓氭繆绂嗛妴涓痮de 閸?`captcha_node/node_modules`閵?
## 2. 閸氼垰濮╅崣鍌涙殶

```powershell
Copy-Item .env.example .env
notepad .env
```

閼峰啿鐨拋鍓х枂閿?
```dotenv
PRO_ZAI_PASSWORD=<鐠佸潡妫堕幒褍鍩楅崣鎵畱閸欙絼鎶?
PRO_ZAI_SESSION_SECRET=<闂呭繑婧€闂€鍨摟缁楋缚瑕?
TZ=Asia/Shanghai
```

鐠佸潡妫堕崷鏉挎絻閿涙瓪http://SERVER_IP:8009`閵嗗倹婀拋鍓х枂 `PRO_ZAI_PASSWORD` 閺冭埖甯堕崚璺哄酱娑撳秴鎯庨悽銊ф瑜版洟妫妴?
## 3. 閺佺増宓侀幐浣风畽閸?
`compose.yaml` 鐏忓棗顔栨稉缁樻簚 `./data` 閹稿倽娴囬崚?`/app/data`閿?
- `data/config.json`
- `data/tasks.json`

閺囧瓨鏌婇梹婊冨剼娑撳秳绱伴崚鐘绘珟娴犺濮熼妴渚€鍋栫粻?JWT 閹存牞澶勯崣鐑藉帳缂冾喓鈧倷绗夌憰浣瑰Ω `data/` 閹绘劒姘﹂崚?Git閵?
## 4. 閺堝秴濮熼崳銊╁劥缂?
閺堝秴濮熼崳銊ュ嚒鐎瑰顥?Docker閿涘奔绲鹃崣顏呭絹娓?`docker-compose` 1.29閵嗗倷濞囬悽銊︽拱閺堥缚鍓奸張顒佸Ω闂€婊冨剼閸?闁板秶鐤嗘导鐘插煂閺堝秴濮熼崳顭掔窗

```powershell
$env:PRO_ZAI_SSH_HOST = "<server-host>"
$env:PRO_ZAI_SSH_USER = "<ssh-user>"
$env:PRO_ZAI_SSH_PASSWORD = "<SSH 鐎靛棛鐖?"
$env:PRO_ZAI_WEB_PASSWORD = "<WebUI 閸欙絼鎶?"
$env:PRO_ZAI_SESSION_SECRET = "<闂呭繑婧€闂€鍨摟缁楋缚瑕?"
python remote_build.py
```

`remote_build.py` 閸欘亙绗傛导鐘崇爱閻礁甯囩紓鈺佸瘶閿涘苯婀張宥呭閸ｃ劎娲块幒銉﹀閸?Playwright 閸╄櫣顢呴梹婊冨剼楠炶埖鐎鐚寸礉
闁灝鍘ら柅姘崇箖閹便垽鈧?SSH 娑撳﹣绱?1 GB 闂€婊冨剼閵嗗倽瀚㈤張宥呭閸ｃ劍鐎楦跨カ濠ф劒绗夌搾绛圭礉閸欘垱鏁奸悽?`deploy_server.py` 娑撳﹣绱堕張顒佹簚瀹稿弶鐎铏规畱 `pro-zai:local` 闂€婊冨剼閵?
鏉╂粎鈻奸弸鍕紦閼存碍婀版导姘剧窗

1. 娑撳﹣绱跺┃鎰垳娑撳酣鍎寸純鏌ュ帳缂?2. 閸︺劍婀囬崝鈥虫珤閹笛嗩攽 `docker build -t pro-zai:latest .`
3. 閹笛嗩攽 `docker-compose up -d --force-recreate`
4. 娴犲孩婀囬崝鈥虫珤閺堫剚婧€鐠囬攱鐪?`/api/health`

## 5. 鏉╂劘顢戝Ο鈥崇础

閺堝秴濮熼崳銊ф纯鏉╃偞鏁為崘宀勨偓澶嬪 `registration_mode=direct`閵嗗倽顔栫€诡澀绱扮拠婵勨偓浣藉閸欑兘顣╁Λ鈧妴涔籭gnup閵?闁喚顔堝┑鈧ú璇叉嫲 OAuth 闁垝濞囬悽銊ユ倱娑撯偓娑?HTTP 娴兼俺鐦介敍娑㈢崣鐠囦胶鐖滈柅澶嬪
`protocol_captcha_mode=browser` 閺冭绱濋崣顏勬儙閸斻劋绔存稉顏冨閺?Playwright 妞ょ敻娼伴懢宄板絿娴滃搫浼?濠婃垵娼￠崙顓＄槈閿涘本绁荤憴鍫濇珤閸欐垵鍤惃?signup 鐠囬攱鐪版导姘躬閸掓稑缂撶拹锕€褰块崜宥嗗閹搭亷绱濋梾蹇撴倵閸戭叀鐦夐崪?Cookie
閸ョ偞鏁為崢鐔峰礂鐠侇喕绱扮拠婵撶礉閻㈠崬宕楃拋顔碱吂閹撮顏€瑰本鍨氶崬顖欑娑撯偓濞?signup閵?
濞夈劌鍞介崜宥勫▏閻?`POST /api/v1/auths/forgot-password` 閸嬫岸娼崘娆忓弳鐠愶箑褰挎０鍕梾閿涙艾鍑″▔銊ュ斀闁喚顔?鏉╂柨娲?`success=true`閿涘本婀▔銊ュ斀鏉╂柨娲?`success=false` 閸滃备鈧粏顕氶柇顔绢唸閺堫亝鏁為崘灞糕偓婵勨偓鍌氭嚒娑擃厼鍑″▔銊ュ斀
閺冩湹鎹㈤崝陇绻橀崗?`SKIPPED_EXISTING`閿涘奔绗夋导姘辨埛缂侇參鐛欑拠浣虹垳閹存牕鍨卞楦垮閸欐灚鈧?
## 6. 8 閺?8 GB 瀵ら缚顔?
- `concurrency=1`
- `captcha_runtime_max_concurrency=1`
- 娑撳秴鎯庨悽銊潒鐟欏鍘规惔鏇炶嫙閸?- 濮ｅ繋閲?Chromium 鐎圭偘绶ョ痪锕€宕?1閳?.5 GB閿涘本澹掗柌蹇庢崲閸斺€插▏閻劌宕熺捄顖涙纯缁?- `shm_size: 1gb` 瀹歌尪顔曠純顕嗙礉闁灝鍘?Chromium 閸忓彉闊╅崘鍛摠娑撳秷鍐?
## 7. 鏉╂劗娣?
```bash
cd <deployment-directory>
docker-compose ps
docker-compose logs -f --tail=200
docker-compose restart
docker-compose down
```

閺囧瓨鏌婇悧鍫熸拱閺冨爼鍣搁弬鐗堢€鎭掆偓浣风瑐娴肩娀鏆呴崓蹇ョ礉閸愬秵澧界悰?`docker-compose up -d --force-recreate`閵?`/app/data` 娑撳秴婀梹婊冨剼閸愬拑绱濋幍鈧禒銉╁櫢閸氼垯绗岄弴鎸庡床鐎圭懓娅掓稉宥勭窗娑擃澀鎹㈤崝掳鈧?
## 8. 鏉╂粎鈻肩拋鍧楁６

`8009` 閺勵垱妲戦弬?HTTP 缁旑垰褰涢妴鍌氼洤閺嬫粍婀囬崝鈥虫珤瀹稿弶婀?Caddy/Nginx閿涘苯缂撶拋顔肩殺 `8009` 閸欘亞绮︾€规艾鍩?`127.0.0.1`閿涘苯鍟€閻㈣京骞囬張?HTTPS 閸欏秳鍞弳鎾苟閸╃喎鎮曢敍娑橆洤閺嬫粈澶嶉弮鏈靛▏閻劌鍙曠純?IP閿涘苯濮熻箛鍛邦啎缂?`PRO_ZAI_PASSWORD`閿涘苯鑻熼梽鎰煑闂冭尙浼€婢ф瑦娼靛┃?IP閵?