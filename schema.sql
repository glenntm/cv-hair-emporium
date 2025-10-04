--
-- PostgreSQL database dump
--

\restrict 4PCJ8gfUgWxOqHbTC8VYp9OUIwqgOcDMiAObcY3iYvEOPitzASRWuxdsA5fu9dV

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: glenntm
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO glenntm;

--
-- Name: reviews; Type: TABLE; Schema: public; Owner: glenntm
--

CREATE TABLE public.reviews (
    id integer NOT NULL,
    user_id integer NOT NULL,
    rating integer,
    comment text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT reviews_rating_check CHECK (((rating >= 1) AND (rating <= 5)))
);


ALTER TABLE public.reviews OWNER TO glenntm;

--
-- Name: reviews_id_seq; Type: SEQUENCE; Schema: public; Owner: glenntm
--

CREATE SEQUENCE public.reviews_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.reviews_id_seq OWNER TO glenntm;

--
-- Name: reviews_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: glenntm
--

ALTER SEQUENCE public.reviews_id_seq OWNED BY public.reviews.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: glenntm
--

CREATE TABLE public.users (
    id integer NOT NULL,
    first_name character varying(80) NOT NULL,
    last_name character varying(80) NOT NULL,
    email character varying(120) NOT NULL,
    password character varying(128) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    reset_token character varying(64),
    token_expiration timestamp without time zone,
    old_passwords text[] DEFAULT '{}'::text[]
);


ALTER TABLE public.users OWNER TO glenntm;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: glenntm
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO glenntm;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: glenntm
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: reviews id; Type: DEFAULT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.reviews ALTER COLUMN id SET DEFAULT nextval('public.reviews_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: reviews reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.reviews
    ADD CONSTRAINT reviews_pkey PRIMARY KEY (id);


--
-- Name: users unique_email; Type: CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT unique_email UNIQUE (email);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_reset_token_key; Type: CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_reset_token_key UNIQUE (reset_token);


--
-- Name: reviews fk_user; Type: FK CONSTRAINT; Schema: public; Owner: glenntm
--

ALTER TABLE ONLY public.reviews
    ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict 4PCJ8gfUgWxOqHbTC8VYp9OUIwqgOcDMiAObcY3iYvEOPitzASRWuxdsA5fu9dV

