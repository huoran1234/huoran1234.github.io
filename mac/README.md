# MAC 地址厂商查询

这是一个可直接部署到 GitHub Pages 的纯静态网页。网页运行时只读取 `data` 目录中的 IEEE CSV 文件，不提供在线更新、清除缓存或导入功能。

## 放置 IEEE CSV

请人工从 IEEE Registration Authority 下载以下三个文件，并放到 `data` 目录：

```text
data/mam.csv
data/oui.csv
data/oui36.csv
```

放好后把 `index.html`、`styles.css`、`app.js`、`data/*.csv` 一起提交到 GitHub Pages 即可使用。
