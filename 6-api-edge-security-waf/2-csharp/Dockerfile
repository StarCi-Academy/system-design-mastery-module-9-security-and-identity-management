FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder

WORKDIR /src

COPY waf-gateway.csproj ./
RUN dotnet restore

COPY *.cs ./
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0

WORKDIR /app

COPY --from=builder /app ./

CMD ["dotnet", "waf-gateway.dll"]
