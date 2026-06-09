FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder
WORKDIR /src
COPY api-service.csproj ./
RUN dotnet restore
COPY . ./
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=builder /app ./
EXPOSE 3000
ENTRYPOINT ["dotnet", "fga-opa-api.dll"]
