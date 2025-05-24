use iced::{
    executor, theme::{self, Theme}, widget::{Button, Column, Container, PickList, Row, Text}, window, Application, Color, Command, Degrees, Element, Gradient, Length, Rectangle, Settings, Subscription
};
use iced::widget::canvas::{self, Canvas, Geometry, Path};
use iced::widget::canvas::stroke::{self, Stroke};
use iced::widget::canvas::Style;
use iced::widget::container;
use iced::Background;
use iced::widget::button;
use std::path::PathBuf;
use iced::gradient::Linear;
use iced::Command as IcedCommand;
use iced::event::{self, Event};
use iced::subscription;
use iced::mouse;

pub fn main() -> iced::Result {
    Locker::run(Settings {
        window: window::Settings {
            size: (800, 600),
            resizable: true,
            ..Default::default()
        },
        ..Default::default()
    })
}

#[derive(Debug, Clone)]
enum Message {
    FileDropped(PathBuf),
    FileSelected(PathBuf),
    OpenPressed,
    SelectFilePressed,
    NewPressed,
}

struct Locker {
    selected_path: Option<PathBuf>,
}

impl Application for Locker {
    type Message = Message;
    type Theme = Theme;
    type Executor = executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            Locker {
                selected_path: None,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("Locker")
    }

    fn subscription(&self) -> Subscription<Message> {
        subscription::events_with(|event, _| {
            if let Event::Window(window::Event::FileDropped(path)) = event {
                Some(Message::FileDropped(path))
            } else {
                None
            }
        })
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::FileDropped(path) => {
                self.selected_path = Some(path);
                Command::none()
            }
            Message::FileSelected(path) => {
                self.selected_path = Some(path);
                Command::none()
            }
            Message::OpenPressed => {
                // TODO: Implement open functionality
                Command::none()
            }
            Message::SelectFilePressed => {
                Command::perform(
                    async {
                        let handle = rfd::FileDialog::new()
                            .add_filter("All Files", &["*"])
                            .pick_file();
                        handle
                    },
                    |path| {
                        if let Some(path) = path {
                            Message::FileSelected(path)
                        } else {
                            todo!()
                        }
                    },
                )
            }
            Message::NewPressed => {
                // TODO: Implement new functionality
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        let drop_zone = Container::new(
            Canvas::new(DropZone::new())
                .width(Length::Fill)
                .height(Length::FillPortion(5))
        )
        .width(Length::Fill)
        .height(Length::FillPortion(5))
        .padding(10)
        .style(iced::theme::Container::Custom(Box::new(DarkGradientStyle)));

        let file_picker = Container::new(
            Row::new()
                .push(
                    Button::new(
                        Text::new("Select File")
                            .horizontal_alignment(iced::alignment::Horizontal::Center)
                            .vertical_alignment(iced::alignment::Vertical::Center)
                    )
                    .on_press(Message::SelectFilePressed)
                    .padding(10)
                    .width(Length::Fixed(150.0))
                    .style(iced::theme::Button::Custom(Box::new(DarkButtonStyle)))
                )
                .push(
                    Text::new(
                        self.selected_path
                            .as_ref()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| "No file selected".to_string())
                    )
                )
                .align_items(iced::Alignment::Center)
                .spacing(20)
        )
        .width(Length::Fill)
        .height(Length::FillPortion(3))
        .center_x()
        .center_y()
        .align_x(iced::alignment::Horizontal::Center);

        let open_button = Container::new(
            Button::new(
                Text::new("Open")
                    .size(24)
                    .horizontal_alignment(iced::alignment::Horizontal::Center)
                    .vertical_alignment(iced::alignment::Vertical::Center)
            )
            .on_press(Message::OpenPressed)
            .padding(10)
            .width(Length::Fixed(200.0))
            .style(iced::theme::Button::Custom(Box::new(DarkButtonStyle)))
        )
        .width(Length::Fill)
        .height(Length::FillPortion(1))
        .center_x()
        .center_y();

        let separator = Container::new(
            Row::new()
                .push(
                    Container::new(Text::new(""))
                        .width(Length::Fixed(100.0))
                        .height(Length::Fixed(1.0))
                        .style(iced::theme::Container::Custom(Box::new(SeparatorStyle)))
                )
                .push(
                    Text::new("or")
                        .horizontal_alignment(iced::alignment::Horizontal::Center)
                )
                .push(
                    Container::new(Text::new(""))
                        .width(Length::Fixed(100.0))
                        .height(Length::Fixed(1.0))
                        .style(iced::theme::Container::Custom(Box::new(SeparatorStyle)))
                )
                .align_items(iced::Alignment::Center)
                .spacing(10)
        )
        .width(Length::Fill)
        .height(Length::FillPortion(1))
        .center_x()
        .center_y();

        let new_button = Container::new(
            Button::new(
                Text::new("New")
                    .size(24)
                    .horizontal_alignment(iced::alignment::Horizontal::Center)
                    .vertical_alignment(iced::alignment::Vertical::Center)
            )
            .on_press(Message::NewPressed)
            .padding(10)
            .width(Length::Fixed(200.0))
            .style(iced::theme::Button::Custom(Box::new(DarkButtonStyle)))
        )
        .width(Length::Fill)
        .height(Length::FillPortion(1))
        .center_x()
        .center_y();

        Container::new(
            Column::new()
                .push(drop_zone)
                .push(file_picker)
                .push(open_button)
                .push(separator)
                .push(new_button)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_items(iced::Alignment::Center)
                .spacing(10)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(iced::theme::Container::Custom(Box::new(DarkBackgroundStyle)))
        .into()
    }
}

struct DropZone {
    cache: canvas::Cache,
}

impl DropZone {
    fn new() -> Self {
        Self {
            cache: canvas::Cache::new(),
        }
    }
}

impl canvas::Program<Message> for DropZone {
    type State = ();

    fn draw(&self, _state: &(), renderer: &iced::Renderer, _theme: &Theme, bounds: Rectangle, _cursor: iced::mouse::Cursor) -> Vec<Geometry> {
        let geometry = self.cache.draw(renderer, bounds.size(), |frame| {
            let center = frame.center();
            let radius = frame.width().min(frame.height()) * 0.4;

            let circle = Path::circle(center, radius);
            frame.stroke(
                &circle,
                Stroke::default()
                    .with_color(Color::from_rgb(0.5, 0.5, 0.5))
                    .with_width(2.0),
            );

            frame.fill_text(iced::widget::canvas::Text {
                content: "Drop File Here".to_string(),
                position: center,
                color: Color::from_rgb(0.7, 0.7, 0.7),
                size: 20.0,
                horizontal_alignment: iced::alignment::Horizontal::Center,
                vertical_alignment: iced::alignment::Vertical::Center,
                ..Default::default()
            });
        });

        vec![geometry]
    }

    fn mouse_interaction(&self, _state: &(), bounds: Rectangle, cursor: iced::mouse::Cursor) -> iced::mouse::Interaction {
        if cursor.is_over(bounds) {
            iced::mouse::Interaction::default()
        } else {
            iced::mouse::Interaction::default()
        }
    }
}

struct DarkGradientStyle;

impl container::StyleSheet for DarkGradientStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.15, 0.15, 0.15))),
            ..Default::default()
        }
    }
}

struct DarkBackgroundStyle;

impl container::StyleSheet for DarkBackgroundStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.18, 0.18, 0.18))),
            ..Default::default()
        }
    }
}

struct DarkButtonStyle;

impl button::StyleSheet for DarkButtonStyle {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.25, 0.25, 0.25))),
            border_radius: 5.0.into(),
            border_width: 1.0,
            border_color: Color::from_rgb(0.3, 0.3, 0.3),
            text_color: Color::from_rgb(0.9, 0.9, 0.9),
            ..Default::default()
        }
    }

    fn hovered(&self, _style: &Self::Style) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.3, 0.3, 0.3))),
            border_radius: 5.0.into(),
            border_width: 1.0,
            border_color: Color::from_rgb(0.35, 0.35, 0.35),
            text_color: Color::from_rgb(1.0, 1.0, 1.0),
            ..Default::default()
        }
    }

    fn pressed(&self, _style: &Self::Style) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.2, 0.2, 0.2))),
            border_radius: 5.0.into(),
            border_width: 1.0,
            border_color: Color::from_rgb(0.25, 0.25, 0.25),
            text_color: Color::from_rgb(0.8, 0.8, 0.8),
            ..Default::default()
        }
    }
}

struct SeparatorStyle;

impl container::StyleSheet for SeparatorStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.4, 0.4, 0.4))),
            ..Default::default()
        }
    }
}
