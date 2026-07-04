use crate::catalog::{route_profile_by_name, signal_by_name, SIGNAL_SPECS};
use crate::checksum::rolling_tag;
use crate::error::{Diagnostics, IronfleetError, Result};
use crate::model::{RouteLeg, Waypoint};
use crate::text::{as_lossy_text, find_pair, parse_f64, parse_pairs, parse_u32, split_record};

#[derive(Debug, Clone, Default)]
pub struct RouteBook {
    pub routes: Vec<RouteLeg>,
    pub waypoints: Vec<Waypoint>,
    pub diagnostics: Diagnostics,
    pub score: u32,
}

impl RouteBook {
    pub fn validate(&mut self) {
        for route in &self.routes {
            if route.origin == route.destination {
                self.diagnostics.push(IronfleetError::low("route origin matches destination").with_context(route.id.clone()));
            }
            if route.distance_m == 0 {
                self.diagnostics.push(IronfleetError::medium("route has zero distance").with_context(route.id.clone()));
            }
            if route.risk > 90 && !route.tags.iter().any(|tag| tag == "escort") {
                self.diagnostics.push(IronfleetError::high("high-risk route lacks escort tag").with_context(route.id.clone()));
            }
        }
        for point in &self.waypoints {
            if !(-90.0..=90.0).contains(&point.lat) || !(-180.0..=180.0).contains(&point.lon) {
                self.diagnostics.push(IronfleetError::medium("waypoint coordinate outside range").with_context(point.route.clone()));
            }
        }
    }

    pub fn route_for(&self, id: &str) -> Option<&RouteLeg> { self.routes.iter().find(|route| route.id == id) }

    pub fn waypoints_for<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a Waypoint> + 'a {
        self.waypoints.iter().filter(move |point| point.route == id)
    }
}

pub fn parse_route_manifest(data: &[u8]) -> Result<RouteBook> {
    let text = as_lossy_text(data);
    let mut book = RouteBook::default();
    for (line_no, raw) in text.lines().enumerate() {
        let Some((kind, rest)) = split_record(raw) else { continue; };
        match kind.to_ascii_lowercase().as_str() {
            "route" => match parse_route_line(rest) {
                Ok(route) => {
                    book.score = book.score.rotate_left(3) ^ rolling_tag(line_no as u32, route.id.as_bytes());
                    book.routes.push(route);
                }
                Err(err) => book.diagnostics.push(err.at(line_no)),
            },
            "waypoint" => match parse_waypoint_line(rest) {
                Ok(point) => {
                    book.score = book.score.rotate_left(5) ^ point.index;
                    book.waypoints.push(point);
                }
                Err(err) => book.diagnostics.push(err.at(line_no)),
            },
            "sensor" => {
                let pairs = parse_pairs(rest);
                if let Some(id) = find_pair(&pairs, "id") {
                    if signal_by_name(id).is_none() {
                        book.diagnostics.push(IronfleetError::low("unknown sensor id in route manifest").at(line_no).with_context(id.to_string()));
                    }
                }
            }
            "profile" => {
                let pairs = parse_pairs(rest);
                if let Some(name) = find_pair(&pairs, "name") {
                    if route_profile_by_name(name).is_none() {
                        book.diagnostics.push(IronfleetError::low("unknown route profile").at(line_no).with_context(name.to_string()));
                    }
                }
            }
            "iftl/1" | "ifss/1" => {}
            _ => book.diagnostics.push(IronfleetError::info("unhandled route manifest line").at(line_no).with_context(kind.to_string())),
        }
        if book.routes.len() > 2048 || book.waypoints.len() > 8192 {
            return Err(IronfleetError::medium("route manifest exceeds decoder limits"));
        }
    }
    book.validate();
    Ok(book)
}

pub fn parse_route_line(rest: &str) -> Result<RouteLeg> {
    let pairs = parse_pairs(rest);
    let id = find_pair(&pairs, "id").unwrap_or("route-unknown").to_string();
    let origin = find_pair(&pairs, "from").or_else(|| find_pair(&pairs, "origin")).unwrap_or("UNKNOWN").to_string();
    let destination = find_pair(&pairs, "to").or_else(|| find_pair(&pairs, "destination")).unwrap_or("UNKNOWN").to_string();
    let distance_m = find_pair(&pairs, "distance").or_else(|| find_pair(&pairs, "meters")).map(parse_u32).transpose()?.unwrap_or(0);
    let mut risk = find_pair(&pairs, "risk").map(parse_u32).transpose()?.unwrap_or(0).min(100) as u8;
    if let Some(profile) = find_pair(&pairs, "profile").and_then(route_profile_by_name) {
        risk = risk.saturating_add(profile.risk_bias).min(100);
    }
    let tags = find_pair(&pairs, "tags")
        .unwrap_or("")
        .split('|')
        .filter(|tag| !tag.is_empty())
        .map(|tag| tag.to_ascii_lowercase())
        .collect();
    Ok(RouteLeg { id, origin, destination, distance_m, risk, tags })
}

pub fn parse_waypoint_line(rest: &str) -> Result<Waypoint> {
    let pairs = parse_pairs(rest);
    let route = find_pair(&pairs, "route").unwrap_or("route-unknown").to_string();
    let index = find_pair(&pairs, "index").or_else(|| find_pair(&pairs, "idx")).map(parse_u32).transpose()?.unwrap_or(0);
    let lat = find_pair(&pairs, "lat").map(parse_f64).transpose()?.unwrap_or(0.0);
    let lon = find_pair(&pairs, "lon").map(parse_f64).transpose()?.unwrap_or(0.0);
    let dwell_seconds = find_pair(&pairs, "dwell").map(parse_u32).transpose()?.unwrap_or(0);
    Ok(Waypoint { route, index, lat, lon, dwell_seconds })
}

pub fn route_signal_digest(book: &RouteBook) -> u32 {
    let mut digest = book.score ^ (SIGNAL_SPECS.len() as u32);
    for route in &book.routes {
        digest = digest.rotate_left(7) ^ route.distance_m ^ ((route.risk as u32) << 24);
    }
    for point in &book.waypoints {
        digest = digest.rotate_left(3) ^ point.index ^ point.dwell_seconds;
    }
    digest
}
