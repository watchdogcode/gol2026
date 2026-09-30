# Referencia KQL para notebooks

Funciones usadas por los notebooks:

- `fn_Normalize_Windows_DHCP(Lookback)`
- `fn_Normalize_Windows_DNS(Lookback)`
- `fn_Correlate_DHCP_DNS(Lookback, LeaseWindow)`

## Validacion rapida

```kql
fn_Normalize_Windows_DHCP(1d)
| take 10
```

```kql
fn_Normalize_Windows_DNS(1d)
| take 10
```

```kql
fn_Correlate_DHCP_DNS(1d)
| take 10
```
