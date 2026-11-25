# 配布資材の確認

公開鍵は別経路でSHA256とfingerprintを照合してから採用する。

```sh
sha256sum release-public-key.pub
openssl pkey -pubin -in release-public-key.pub -outform DER | openssl dgst -sha256 -binary | openssl base64 -A
```

public key SHA256は`6adf5e38d694aa4b16c74c28e50bb197e4d617035b39e03aaad8e7d39e973e5e`。

`publication.json`はUTF-8/ASCIIのcanonical JSONである。`publication.sig`は同文書に対するEd25519署名のbase64表現である。

```sh
openssl base64 -d -A -in publication.sig -out publication.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey release-public-key.pub \
  -in publication.json -sigfile publication.sig.bin
```

署名確認後、publication.jsonのassetsにある各ファイルのsha256・bytesをダウンロードした実物と照合する。更新workerはさらにrelease.json・release.sig・更新archive内のmanifestと各payloadを検証する。

新規サイトでのCA/issuer、TLS、DNS、通知先とバックアップは導入先の手順で準備する。詳細は導入archive内のINSTALLATION.mdを参照する。

## 公開審査

リリース担当者は、公開する履歴と全資材、別ドメインで生成した設定を展開して、運用値や資格情報の混入を検査します。バックアップMXは任意です。副系を配置しない構成での新規導入、通常更新、故障時の復旧を記録し、署名対象と検証済みの資材を照合してから公開します。

## 公開前の検査

署名前に製品ソース、テスト、インストーラー、更新用資材とその生成物を展開し、非公開の開発先や運用識別子が含まれないことを検査します。署名後も配布ファイル全件と、公開予定のブランチ・タグから取得できる履歴を再検査します。未検査または不一致の資材は公開できません。
