# Configuração do Supabase — ATENÇÃO PRO

## 1. Criar as tabelas e políticas

1. Abra o projeto Supabase correto.
2. Entre em **SQL Editor** → **New query**.
3. Abra o arquivo [schema.sql](./schema.sql), copie todo o conteúdo e execute.
4. Confira se a execução terminou sem erros.

## 2. Configuração do projeto

Project URL:
`https://bxfjqumgfwolkunhtfhw.supabase.co`

A Publishable Key deve ser configurada no frontend apenas depois da revisão da integração. Nunca use a chave `service_role` no site.

## 3. O que o esquema protege

- Perfis começam como responsável; o papel de psicólogo exige promoção manual por administrador.
- Responsáveis criam e controlam perfis infantis usando apelidos.
- O psicólogo só vê progresso de crianças com vínculo ativo.
- O responsável autoriza o vínculo ao reivindicar um convite.
- O responsável pode revogar o vínculo.
- Eventos e progresso ficam separados; psicólogos têm leitura, não escrita.
- RLS está ativado em todas as tabelas e não há acesso anônimo.

## 4. Limites desta primeira etapa

Este arquivo cria a estrutura do banco, mas não instala sozinho uma interface de login, criação de perfis, convites ou sincronização no jogo. Essas telas e a integração com o código precisam ser implementadas e testadas antes de usar com dados reais.

O esquema é uma base inicial, não uma certificação de conformidade legal ou clínica. Use apenas com autorização do responsável, dados mínimos e teste de permissões. Não cadastre dados identificáveis ou informações clínicas sensíveis nesta fase.
