--
-- PostgreSQL database dump
--

\restrict B7ezgGI1bt04b5Z3lOwxsWdcE2Eb9SNG2Jz7QWuZEY5NCDdpw0duDf2TxgKqvsU

-- Dumped from database version 14.19 (Ubuntu 14.19-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.19 (Ubuntu 14.19-0ubuntu0.22.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: glenntm
--

COPY public.alembic_version (version_num) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: glenntm
--

COPY public.users (id, first_name, last_name, email, password, created_at, reset_token, token_expiration, old_passwords) FROM stdin;
1	Bobo	Bobo	Bobo@bobo.com	$2b$12$Q/IqYVKwkOnlerpaBURQwe71i9yZQp5BX5Jix9eW8CHsgQkwyAbgS	2024-11-25 10:41:10.149116	\N	\N	{}
2	Test	Testiee	test@test.com	$2b$12$HYCY2MQY3rW.C2YZz.ByAey.lslnEAadxpIYPI8d2CYxpTgTrxOIW	2024-11-25 10:41:10.149116	\N	\N	{}
3	Dave	Dave	dave@dave.com	$2b$12$9O59fEJRZrYa2wXVw5PqiuEaryYZm7GOAWxpdODp.dn3tESUJRoz2	2024-11-25 10:41:10.149116	\N	\N	{}
9	Glenn	Telus-Mensah	glenn.telusmensah@gmail.com	$2b$12$jLShpNFq1U4Z6Pli68lh9.Pi4DHEoQEoYexC3o7nY2Dg9CHnYHtwy	2024-11-25 10:41:10.149116	\N	\N	{}
10	David	Goggins	dgoggins@gmail.com	$2b$12$IMBEKeFdfgTQF1l/cQBnoOg8WBtxteNticO.srOf2o92feGdvfzrC	2024-11-25 10:41:10.149116	\N	\N	{}
11	Try	Me	try@me.com	$2b$12$El9WyMgj9L19VjNRHsK9pOb3K0/.vyHlBpAYKq5gYZPKoiXswmHyO	2024-11-25 10:41:10.149116	\N	\N	{}
13	Hobo	Hobo	hobo@me.com	$2b$12$MwdGgOuyI6b73XbXNBfug.4jEky3Xm/8So6dPAFIi/C1RrBCM0fNO	2024-11-25 10:41:10.149116	\N	\N	{}
14	OGG	ddd	oggg@g.com	$2b$12$eVOjY4wb5aiVA2JNu.rGZ.6vJmROUl0OzxAt8MdMSXenVAfE9O7d6	2024-11-25 16:48:52.334685	\N	\N	{}
15	Mama	Mia	mia@me.com	$2b$12$R0GByKlLX152tv6IN60QIOr8UXjJnECu2YfBmHXf4dLBJLxIUfuQi	2024-11-25 16:56:52.366559	\N	\N	{}
8	Glenn	Telus-Mensah	danotoriousg@gmail.com	$2b$12$E8jqHM2k1RmAe6nDD00Cpuv3DtuLgEnj1pfSSvZg3F.TFyvxCmNQq	2024-11-25 10:41:10.149116	\N	\N	{}
20	Don	Julio	don@meme.com	$2b$12$4Ed7WPg1JhWIx4P2jWhw9.cH8aJkepyOZMVrti3Ar7WG2b78A/YGm	2025-01-27 14:51:27.785582	\N	\N	{}
17	Mick	Jenkins	mick@jenkins.com	$2b$12$FWONuM8zJYzjShNWBme9KefONlmoZcrJIoipRo/7JvuuZ3qZLv4bi	2024-12-23 08:34:56.498205	\N	\N	{}
18	DD	DD	dd@dd.com	$2b$12$K0Ty/L4vRGrL6XH7T1L5eOnZhzWnhnNSW8lxqnMPz4mAim5i05iBi	2024-12-23 10:58:20.199041	\N	\N	{}
19	OG	Meatcakes	me@meat.com	$2b$12$SAPWNbaqUl4LAUUmszLU.O83/V.Wfpj5LktVQTouTs9lQf9t5F5JO	2025-01-14 20:50:42.787283	\N	\N	{}
16	Glenn	Telus-Mensah	glenntm1@live.com	$2b$12$n2odUVqZwyV6XOlvWYEkP.uFpgrALBj8FRRYT08xx6KrVfJo3VCFm	2024-12-10 05:47:26.453676	163bb07e6fa8eff21f411202bc88f1449076435b066d1f57682ce344ebe7fb3f	2025-03-16 15:48:01.142465	{$2b$12$By4BUoiuSVoP2aPdTKrg3.S4/4HdGL9/Tw6SZNRSTbstFmA.83wxm}
\.


--
-- Data for Name: reviews; Type: TABLE DATA; Schema: public; Owner: glenntm
--

COPY public.reviews (id, user_id, rating, comment, created_at, updated_at) FROM stdin;
1	16	5	It was great!	2025-01-11 11:19:21.394606	2025-01-11 11:19:21.394606
2	16	3	Mid	2025-01-11 11:21:48.961791	2025-01-11 11:21:48.961791
4	20	4	Great service! would go again	2025-01-27 15:02:57.602607	2025-01-29 01:08:36.094375
5	8	4	Muy Bueno	2025-01-29 20:32:23.706473	2025-01-29 20:32:23.706473
6	8	5	Would come back again. Test test	2025-01-29 20:36:20.615286	2025-03-12 02:03:43.777714
3	16	5	Eggselente	2025-01-11 12:06:58.128076	2025-05-09 01:55:42.508769
\.


--
-- Name: reviews_id_seq; Type: SEQUENCE SET; Schema: public; Owner: glenntm
--

SELECT pg_catalog.setval('public.reviews_id_seq', 6, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: glenntm
--

SELECT pg_catalog.setval('public.users_id_seq', 20, true);


--
-- PostgreSQL database dump complete
--

\unrestrict B7ezgGI1bt04b5Z3lOwxsWdcE2Eb9SNG2Jz7QWuZEY5NCDdpw0duDf2TxgKqvsU

