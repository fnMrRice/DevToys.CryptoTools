# DevToys.CryptoTools

DevToys 2.0 加解密插件，使用 .NET 8 和 `DevToys.Api 2.0.10-preview`。

## 开发

```powershell
dotnet restore
dotnet build -c Release
dotnet test -c Release
dotnet pack src/DevToys.CryptoTools -c Release -o artifacts
```

在 DevToys 的“管理扩展”中安装生成的 `.nupkg`，重启后使用。

接口和打包方式参照 [DevToys 扩展开发文档](https://devtoys.app/doc/articles/extension-development/getting-started/create-an-extension.html)。

所有密码运算在本地执行，不记录或持久化输入的私钥和明文。
